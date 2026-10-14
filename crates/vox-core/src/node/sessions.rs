//! Session lifecycle records (ADR-031 SA-3) share the private, drive-sealed Session stream.
//! Opening, rename and end records are not activity steps: a new drive grant receives their
//! retained state, with original times, without receiving earlier activity. Legacy room records
//! remain readable in copies already held (SA-5).

/// Bounded identity/name selection shared by terminal and TUI callers.
pub mod selection;

use vox_agentcomms::envelope::{Envelope, SESSION, SESSION_END};

use crate::hash::Digest32;
use crate::node::actor::NodeHandle;
use crate::node::api::{Fault, NodeCommand, Outcome};

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

/// A continuation for pending requests in one unchanged room/authority revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingCursor {
    /// Opaque input/authority stamp; a changed room refuses continuation.
    pub revision: Digest32,
    /// Last examined saved private arrival, not an unbounded set of prior requests.
    pub after: u64,
}

/// One addressable waiting request. Full metadata/details are read only on selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTarget {
    /// Authenticated Session author.
    pub node: Digest32,
    /// Complete Session id, within the existing content format bound.
    pub id: String,
    /// Current open Session's opening.
    pub opening: Digest32,
    /// The approval/question origin to fetch with the existing exact activity path.
    pub entry: Digest32,
}

/// A position in the chronological opening/end notices of one saved room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleCursor {
    /// The opening or end time, in milliseconds.
    pub at_millis: u64,
    /// The Session's opening entry, used to validate the retained position.
    pub opening: Digest32,
    /// An end notice rather than an opening.
    pub ended: bool,
}

/// One lifecycle notice with complete current metadata for its usual label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleRow {
    /// Complete metadata; large fields are carried across bounded transport chunks.
    pub session: SessionRow,
    /// This notice's exact position and kind.
    pub cursor: LifecycleCursor,
}

/// Exact own/current-author lookup. Pending policy and Session folds retry within the same
/// deadline; neither the actor nor a waiting client retains all Session metadata.
pub(crate) async fn lookup(
    handle: &NodeHandle,
    room: Digest32,
    node: Digest32,
    id: &str,
) -> Result<Option<crate::node::channel::session_projection::Row>, String> {
    use crate::node::channel::session_projection::{Query, Reply};
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match handle
            .session_projection(
                room,
                Query::Lookup {
                    node,
                    id: id.to_owned(),
                },
            )
            .await
        {
            Ok(Reply::Lookup(row)) => return Ok(row),
            Ok(_) => return Err("unexpected Session lookup answer".into()),
            Err(reason)
                if opening_refreshing(&reason) && tokio::time::Instant::now() < deadline =>
            {
                tokio::task::yield_now().await
            }
            Err(reason) => return Err(reason),
        }
    }
}

// Exact pending replies from governance, legacy classification, private controls and floors,
// and the Session projection. Every other refusal, including unreadable facts, is permanent
// for this attempt and must reach the caller. These are Error::Display strings where the
// actor returns a storage-layer readiness error before reaching the Session query.
fn opening_refreshing(reason: &str) -> bool {
    matches!(
        reason,
        "the room is refreshing saved Sessions; retry"
            | "node: room governance is refreshing; try again when it is ready"
            | "node: legacy Session classification is refreshing"
            | "stream refused: Session authorization facts are refreshing"
            | "stream refused: Session control facts are refreshing"
    )
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
/// node that restarts or a session that resumes never opens a second. One already open under
/// another name is renamed: its record is posted again with the name its harness now gives
/// (MD-1). Call it once the node is a member of `room`.
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
    let open = lookup(handle, room, me, &session.id)
        .await?
        .filter(|row| row.open);
    // **A rename is said at once** (ADR-029 MD-1): the harness renamed its session, and a Session
    // that posts nothing would otherwise keep its old name until its next message. A Session record
    // for one already open names it again (`fold` reads it as the name from then on).
    if open.is_some_and(|row| {
        session.name.as_ref().is_none_or(|name| {
            row.name.is_some_and(|held| {
                held.bytes == name.len() as u64 && held.hash == crate::hash::sha256(name.as_bytes())
            })
        })
    }) {
        return Ok(());
    }
    for part in opening_parts(session) {
        post(handle, room, &session.id, part).await?;
    }
    Ok(())
}

/// Whether this envelope is a lifecycle record, including a part of a large opening.
/// Classification is inside the authenticated, sealed content; it never grants permission.
pub(crate) fn is_record(body: &str) -> bool {
    Envelope::parse(body).is_ok_and(|env| matches!(env.kind.as_str(), SESSION | SESSION_END))
}

/// Opening metadata is sent privately; it carries neither an activity step nor a drive grant.
pub(crate) fn opening_parts(session: &Opening) -> Vec<String> {
    let mut env = Envelope::new(SESSION, "");
    env.from.clone_from(&session.id);
    env.at.session_name.clone_from(&session.name);
    env.data = serde_json::json!({ "session": { "harness": session.harness } });
    metadata_parts(env.to_text())
}

/// A Session's metadata has no field-size limit. Each retained room record still fits the
/// content bound, and the reader joins the complete metadata before exposing any field.
fn metadata_parts(text: String) -> Vec<String> {
    use serde_json::{json, Map, Value};
    let limit = crate::node::content::MAX_TEXT_LEN;
    if text.len() <= limit {
        return vec![text];
    }
    let tag = crate::node::link::b32_encode(&crate::hash::sha256(text.as_bytes()));
    let mut envelope = Map::new();
    envelope.insert("v".into(), json!(1));
    envelope.insert("type".into(), json!(SESSION));
    envelope.insert("body".into(), Value::String(text));
    envelope.insert("data".into(), json!({"session_parts": tag}));
    vox_agentcomms::activity::split(envelope, "body", limit)
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
    let open = lookup(handle, room, me, session)
        .await?
        .is_some_and(|row| row.open);
    if !open {
        return Ok(());
    }
    let mut env = Envelope::new(SESSION_END, "");
    session.clone_into(&mut env.from);
    env.data = serde_json::json!({ "reason": reason });
    post(handle, room, session, env.to_text()).await
}

/// Whether the harness's `reason` for a `SessionEnd` keeps the session open (ADR-029 SE-4).
#[must_use]
pub fn keeps_open(reason: &str) -> bool {
    reason.trim() == "resume"
}

async fn post(
    handle: &NodeHandle,
    room: Digest32,
    session: &str,
    text: String,
) -> Result<(), String> {
    // A room just joined is written to once its first sync with another member has ended
    // (V210-164), and only once its current policy facts are ready. Both pending states use
    // the existing bounded retry; no other failed append is repeated.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match handle
            .apply(NodeCommand::AppendSession {
                channel_id: room,
                session_id: session.to_owned(),
                body: text.clone(),
            })
            .await
        {
            Outcome::Appended(_) => return Ok(()),
            Outcome::Failed(Fault::RoomNotSynced | Fault::GovernanceRefreshing)
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
        put_row(e, r);
    }
}

pub(crate) fn put_row(e: &mut crate::cbor::Encoder, r: &SessionRow) {
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

/// Read what [`put_rows`] wrote.
///
/// # Errors
/// [`crate::error::Error::MalformedIpc`] for anything else.
pub(crate) fn read_rows(d: &mut crate::cbor::Decoder<'_>) -> crate::error::Result<Vec<SessionRow>> {
    read_rows_bounded(d, usize::MAX)
}

pub(crate) fn read_rows_bounded(
    d: &mut crate::cbor::Decoder<'_>,
    limit: usize,
) -> crate::error::Result<Vec<SessionRow>> {
    use crate::error::Error;
    let bad = |what: &'static str| move |_| Error::MalformedIpc(what);
    let digest = |b: &[u8]| {
        Digest32::try_from(b).map_err(|_| Error::MalformedIpc("ipc session digest length"))
    };
    let n = d.array().map_err(bad("ipc sessions"))?;
    if n > limit {
        return Err(Error::MalformedIpc("ipc Session page row count"));
    }
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

/// The id of the one open Session of the node `node` that `typed` names, for a message to address
/// (ADR-029 TA-1, TA-5): its newest opening for each id, so a session that ended and came back is
/// the one that is open. Named as [`resolve`] names one; one that has ended is refused.
///
/// # Errors
/// The refusal, as a sentence: "… has ended", "no Session in this room is named …".
pub fn addressable(
    rows: &[SessionRow],
    node: &Digest32,
    typed: &str,
    label: impl Fn(&SessionRow) -> String,
) -> Result<String, String> {
    let mut mine: Vec<SessionRow> = Vec::new();
    for r in rows.iter().filter(|r| r.node == *node) {
        mine.retain(|m| m.id != r.id);
        mine.push(r.clone());
    }
    resolve(&mine, typed, false, label).map(|s| s.id.clone())
}

/// Refuse a registered session's operation outside its saved working room (ADR-029 RB-3/RB-4).
/// A person may still name an unregistered coordination session at a terminal. Once the hook has
/// registered it, only the deliberate session-room move changes this boundary, never cwd, another
/// session's room or a caller's cached target. Unreadable registrations cannot authorize a post.
///
/// # Errors
/// The registered session works in another room or none, or its registration cannot be read.
pub fn check_working_room(
    paths: &crate::node::paths::Paths,
    session: &str,
    target: &Digest32,
) -> Result<(), String> {
    let session = session.trim();
    if session.is_empty() {
        return Ok(());
    }
    let bytes = match std::fs::read(paths.session_file(session)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "cannot read session {session}'s saved working room: {e}; nothing was posted"
            ))
        }
    };
    let record: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        format!("cannot read session {session}'s saved working room: {e}; nothing was posted")
    })?;
    let target = crate::node::link::b32_encode(target);
    match record.get("room").and_then(serde_json::Value::as_str) {
        Some(room) if room == target => Ok(()),
        room => {
            let working = room.map_or_else(
                || "no room".to_owned(),
                |r| format!("room {}", vox_agentcomms::envelope::shown(r, 64)),
            );
            Err(format!(
                "session {session} works in {working}, not target room {target}; nothing was \
                 posted. Use vox agent room to deliberately move this session"
            ))
        }
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
            let mut metadata = Envelope::new(SESSION, "");
            metadata.from.clone_from(&env.from);
            metadata.at.session_name.clone_from(&env.at.session_name);
            if metadata.to_text().len() <= crate::node::content::MAX_TEXT_LEN {
                env.to_text()
            } else {
                // The complete name is in the Session's authoritative metadata record. Do not
                // make an otherwise valid message fail merely by repeating that metadata.
                text.to_owned()
            }
        }
        None => text.to_owned(),
    }
}
