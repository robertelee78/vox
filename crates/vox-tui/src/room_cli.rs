//! ADR-020 §8 — `vox room`: the agent-facing verbs, over a **running** node.
//!
//! Every other `vox` verb spawns a node of its own. These do not, and that is the
//! point: agent comms puts several agent sessions on one harness node (ADR-020
//! §2, one identity per `(host, harness)`), so these connect to the control
//! socket of a node that is already running and already unlocked.
//!
//! Two consequences fall out of that, both intended:
//!
//! - **No passphrase anywhere.** There is nothing to unlock — the node holds the
//!   identity. An agent session never sees a secret, which is what makes it safe
//!   to hand these verbs to model-authored code.
//! - **No room is created or joined here.** These verbs speak in a room; putting
//!   the node in one is the operator's act.
//!
//! The socket answers a deliberately narrow request set and these verbs are
//! exactly it (`post`, `read`, `tail`, `roster`, `list`). There is no verb here
//! that creates an identity, unlocks, revokes, or edits the trust keyring —
//! `vox trust` is an operator surface and is not part of this module.

use std::io::Read as _;
use std::io::Write as _;
use std::path::Path;

use vox_core::hash::Digest32;
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::link::{b32_decode, b32_encode, B32_DIGEST_LEN};
use vox_core::node::paths::Paths;

use crate::app::AppError;
use crate::tunnel_cli::resolve_prefix;

/// Connect to the running node's control socket for this profile.
///
/// The failure an operator will actually hit is "no node is running", so it says
/// that rather than surfacing a connect error — **and names the thing that would
/// actually fix it.** It used to say "Start one with `vox node`", which is the first
/// error a new person meets and it sent them in a circle: `vox node` is an anchor, it
/// holds no room and serves no control socket, so following the advice produced this
/// same message again, verbatim. `vox daemon` is what holds a profile's rooms and
/// serves this socket.
async fn attach(paths: &Paths) -> Result<IpcClient, AppError> {
    let sock = paths.socket_file();
    if !sock.exists() {
        return Err(AppError::Usage(format!(
            "no node is running for this profile, so there is nothing to ask.\n\
             \x20      Start one:  vox daemon        (holds this profile's rooms, no \
             terminal needed)\n\
             \x20             or:  vox tui           (the interactive client)\n\
             \x20      `vox node` will NOT do: it is an anchor, it holds no room and \
             serves no socket.\n\
             \x20      Socket: {}",
            paths.socket_file().display()
        )));
    }
    IpcClient::open(&sock).await.map_err(|_| {
        AppError::Usage(format!(
            "a control socket exists at {} but nothing answered — the node may have \
             stopped without cleaning up. Starting a node again replaces it.",
            sock.display()
        ))
    })
}

/// Ask the node for its rooms, as `(id, local name, open)`.
async fn rooms_of(client: &mut IpcClient) -> Result<Vec<(Digest32, String, bool)>, AppError> {
    match client.request(&Request::Rooms).await {
        Ok(Frame::Rooms { rooms }) => Ok(rooms),
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// A held-since time, as a person reads it.
///
/// It was printed as raw epoch seconds — `held by … since 1790105354` — which nobody
/// reads, and which is the one number in the message that is supposed to tell you
/// whether to wait or go and find the holder. Both forms are given: the elapsed time
/// answers that question, and the absolute time survives being pasted into a report.
fn held_since(since_secs: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let ago = now.saturating_sub(since_secs);
    let elapsed = if ago < 60 {
        format!("{ago}s ago")
    } else if ago < 3600 {
        format!("{}m ago", ago / 60)
    } else if ago < 86_400 {
        format!("{}h{:02}m ago", ago / 3600, (ago % 3600) / 60)
    } else {
        format!("{}d ago", ago / 86_400)
    };
    // A fixed-offset UTC stamp without pulling in a date library: the fields are
    // arithmetic on the epoch, and the only calendar subtlety is leap years.
    let (days, secs) = (since_secs / 86_400, since_secs % 86_400);
    let (mut y, mut d) = (1970_u64, days);
    loop {
        let len = if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
            366
        } else {
            365
        };
        if d < len {
            break;
        }
        d -= len;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0;
    while m < 12 && d >= months[m] {
        d -= months[m];
        m += 1;
    }
    format!(
        "{y:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z ({elapsed})",
        m + 1,
        d + 1,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Resolve a room prefix against what the node holds, and insist it is open.
///
/// A closed room is reported as closed rather than "unknown": the two are
/// different problems and an operator fixes them differently.
async fn room_of(client: &mut IpcClient, prefix: &str) -> Result<Digest32, AppError> {
    let rooms = rooms_of(client).await?;
    if rooms.is_empty() {
        return Err(AppError::Usage(
            "this node holds no rooms yet — join or create one first".into(),
        ));
    }
    let ids: Vec<Digest32> = rooms.iter().map(|(id, _, _)| *id).collect();
    let id = resolve_prefix(prefix, &ids)?;
    if let Some((_, name, false)) = rooms.iter().find(|(r, _, _)| *r == id) {
        return Err(AppError::Usage(format!(
            "room {name:?} is not open on this node, so there is nothing to read or \
             post — open it in `vox tui`, or start the node with it open"
        )));
    }
    Ok(id)
}

/// Every `vox` verb identifies a room or a member by its **base32** rendering —
/// the same 52 characters that begin an invite link and a `.vox` name — and
/// [`resolve_prefix`] matches prefixes of exactly that. Printing anything else
/// here would produce an id that this CLI cannot resolve from its own output,
/// which is what the first run of the proof test caught.
fn id(d: &Digest32) -> String {
    b32_encode(d)
}

fn short(d: &Digest32) -> String {
    b32_encode(d).chars().take(12).collect()
}

/// `vox room list` — the rooms this node holds.
pub async fn list(paths: &Paths) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let rooms = rooms_of(&mut client).await?;
    if rooms.is_empty() {
        println!("no rooms");
        return Ok(());
    }
    for (id, name, open) in rooms {
        println!(
            "{}  {}{}",
            short(&id),
            if name.is_empty() { "(unnamed)" } else { &name },
            if open { "" } else { "  [closed]" }
        );
    }
    Ok(())
}

/// Read a message body: the argument, or stdin when it is omitted or `-`.
fn body_of(text: Option<&str>) -> Result<String, AppError> {
    match text {
        Some("-") | None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| AppError::Usage(format!("reading stdin: {e}")))?;
            Ok(buf)
        }
        Some(t) => Ok(t.to_owned()),
    }
}

/// Append raw text, exactly as given. The internal path for verbs that build their
/// own envelope (a file offer), and what `vox room post` does with no structured flag.
async fn post(paths: &Paths, room: &str, text: Option<&str>) -> Result<(), AppError> {
    let body = body_of(text)?;
    if body.trim().is_empty() {
        return Err(AppError::Usage("refusing to post an empty message".into()));
    }
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client
        .request(&Request::Post {
            channel_id,
            text: body,
        })
        .await
    {
        Ok(Frame::Ok) => Ok(()),
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// The structured half of `vox room post` (ADR-021 §7).
#[derive(Debug, Clone, Default)]
pub struct PostOpts {
    /// The envelope type. Any structured flag makes the post structured; `say` when
    /// none is given.
    pub kind: Option<String>,
    /// The work item this is about, carried in `data.work`; its shape is checked.
    pub work: Option<String>,
    /// The attempt, carried in `data.attempt`; defaults to this session's claim.
    pub attempt: Option<String>,
    /// Addressees, by petname.
    pub to: Vec<String>,
    /// May interrupt an addressed session.
    pub urgent: bool,
    /// Reply-to entry hash.
    pub re: Option<String>,
    /// Thread root entry hash.
    pub thread: Option<String>,
    /// Extra payload, as a JSON object.
    pub data: Option<String>,
    /// Session, operation id, JSON output.
    pub coord: CoordOpts,
}

impl PostOpts {
    fn is_structured(&self) -> bool {
        self.kind.is_some()
            || self.work.is_some()
            || self.attempt.is_some()
            || !self.to.is_empty()
            || self.urgent
            || self.re.is_some()
            || self.thread.is_some()
            || self.data.is_some()
            || self.coord.op.is_some()
            || self.coord.json
    }
}

/// `vox room post` — append a message.
///
/// With no structured flag, the text is posted exactly as given: prose is a `say`, and
/// an agent may paste an envelope. **Except a claim-protocol operation**, which is
/// refused: it would lack the session, the operation id and the version stamp that
/// make it valid, and the dedicated verbs exist to set them.
///
/// With any structured flag, the CLI builds the envelope itself: it fills `from` and
/// `at`, stamps the version, and posts under an operation id exactly once in effect.
/// A post carrying `--work` takes part in work coordination, so it passes the version
/// gate first (exit 3). A reused `--op` with different content is refused (exit 4).
///
/// # Errors
/// As above, or if the node cannot be reached.
pub async fn post_cmd(
    paths: &Paths,
    room: &str,
    text: Option<&str>,
    opts: &PostOpts,
) -> Result<(), AppError> {
    let body = body_of(text)?;
    if !opts.is_structured() {
        if body.trim().is_empty() {
            return Err(AppError::Usage("refusing to post an empty message".into()));
        }
        if let Ok(env) = Envelope::parse(&body) {
            if claim::is_claim_protocol(&env) {
                return Err(AppError::Usage(format!(
                    "refusing a raw `{}`: claim-protocol operations need a session, an \
                     operation id and a version stamp. Use `vox room {}`.",
                    env.kind, env.kind
                )));
            }
        }
        return post(paths, room, Some(&body)).await;
    }

    let kind = opts.kind.clone().unwrap_or_else(|| "say".into());
    let mut data = match &opts.data {
        None => serde_json::Map::new(),
        Some(raw) => match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(serde_json::Value::Object(m)) => m,
            _ => return Err(AppError::Usage("--data must be a JSON object".into())),
        },
    };
    for reserved in [
        vox_agentcomms::version::VOX_KEY,
        vox_agentcomms::ops::OP_KEY,
    ] {
        if data.contains_key(reserved) {
            return Err(AppError::Usage(format!(
                "--data may not set {reserved:?}: this binary sets it (use --op for the \
                 operation id; the version is never the caller's)"
            )));
        }
    }
    if let Some(w) = &opts.work {
        match data.get(vox_agentcomms::envelope::WORK_KEY) {
            Some(d) if d.as_str() != Some(w) => {
                return Err(AppError::Usage(format!(
                    "--work {w:?} and --data's work {d} differ; name the work item once"
                )))
            }
            _ => {}
        }
        data.insert(vox_agentcomms::envelope::WORK_KEY.into(), w.clone().into());
    }
    // **Whichever flag set it.** The work reference is checked where it lands, not
    // where it was typed: `--data '{"work":…}'` is the same message as `--work`, and
    // checking only the flag let a malformed reference, and the version gate below,
    // be skipped by spelling it the other way.
    let work = match data.get(vox_agentcomms::envelope::WORK_KEY) {
        None => None,
        Some(serde_json::Value::String(w)) if vox_agentcomms::envelope::is_valid_work(w) => {
            Some(w.clone())
        }
        Some(bad) => {
            return Err(AppError::Usage(format!(
                "{bad} is not a work reference: use <scheme>:<id>, the scheme \
                 [a-z][a-z0-9-]{{0,15}} and the id 1–{} of [A-Za-z0-9._~/#:-] \
                 (ADR-021 §3)",
                vox_agentcomms::envelope::MAX_WORK_ID
            )))
        }
    };
    if let Some(a) = &opts.attempt {
        data.insert("attempt".into(), a.clone().into());
    }
    if coord::is_claim_type(&kind, &serde_json::Value::Object(data.clone())) {
        return Err(AppError::Usage(format!(
            "`{kind}` is a claim-protocol operation; use `vox room {kind}`"
        )));
    }
    if body.trim().is_empty() && data.is_empty() {
        return Err(AppError::Usage("refusing to post an empty message".into()));
    }

    let session = coord::require_session(opts.coord.session.as_deref())?;
    let op = match &opts.coord.op {
        Some(op) if vox_agentcomms::ops::is_valid_op(op) => op.clone(),
        Some(op) => {
            return Err(AppError::Usage(format!(
                "--op {op:?} is not an operation id: use 8–64 of [A-Za-z0-9._-]"
            )))
        }
        None => coord::new_op()?,
    };
    let (mut client, cid, room_key) = open_room(paths, room).await?;
    let snap = if work.is_some() {
        coord::participate(&mut client, cid, &room_key, &session).await?
    } else {
        coord::snapshot(&mut client, cid).await?
    };
    // **The attempt, when the caller did not name one** (ADR-021 §3): the acquisition
    // of this session's claim on the work item. A claim is where an attempt begins and
    // a release or lapse is where it ends, so every claim is a new attempt and a tracker
    // can tell a retry from a continuation without asking the agent to mint ids. A
    // retried `--op` keeps the attempt its first post carried — the claim may have been
    // renewed or re-taken since, and a different attempt would make the retry a
    // conflict rather than the same message.
    if let (Some(w), None) = (&work, data.get("attempt")) {
        let earlier = snap
            .posted
            .iter()
            .find(|p| p.author == snap.me && vox_agentcomms::ops::op_of(&p.envelope) == Some(&op))
            .and_then(|p| p.envelope.data.get("attempt").cloned());
        let held = match snap.fold.resources.get(w) {
            Some(State::Held {
                owner, acquisition, ..
            }) if owner.author == snap.me && owner.session == session => {
                Some(serde_json::Value::from(claim::b32(acquisition)))
            }
            _ => None,
        };
        if let Some(a) = earlier.or(held) {
            data.insert("attempt".into(), a);
        }
    }
    let draft = Draft {
        kind,
        to: opts.to.clone(),
        urgent: opts.urgent,
        re: opts.re.clone(),
        thread: opts.thread.clone(),
        body: body.trim_end().to_owned(),
        data,
    };
    let posting = coord::post_once(&mut client, cid, &draft, &session, &op, &snap).await?;
    if opts.coord.json {
        println!(
            "{}",
            serde_json::json!({
                "schema": "vox.room.post/1",
                "room": room_key,
                "entry_hash": claim::b32(&posting.entry_hash),
                "op": posting.op,
                "status": posting.status,
                "session": session,
            })
        );
    }
    Ok(())
}

/// One row as `vox.room.row/1` NDJSON (ADR-021 §7).
///
/// `op.status` is `ok`, `duplicate` or `conflict` against everything the node holds.
/// Rows are in the node's local order, **which is not the canonical order** — sort by
/// `(created_millis, entry_hash)` for a total order.
fn row_json(
    room_key: &str,
    r: &vox_core::node::api::MessageRow,
    ops: &vox_agentcomms::ops::OpIndex,
    status_override: Option<&str>,
) -> String {
    let parsed = Envelope::parse(&r.text);
    let (envelope, parse_error) = match &parsed {
        Ok(e) => (
            serde_json::to_value(e).unwrap_or(serde_json::Value::Null),
            None,
        ),
        Err(e) => (serde_json::Value::Null, Some(e.to_string())),
    };
    let op = parsed.as_ref().ok().and_then(|e| {
        let id = vox_agentcomms::ops::op_of(e)?;
        let (status, group) = match ops.verdict(r.author, e, r.entry_hash) {
            Some(vox_agentcomms::ops::Verdict::Conflict { group }) => ("conflict", group),
            Some(vox_agentcomms::ops::Verdict::Duplicate { .. }) => {
                ("duplicate", ops.group_of(r.author, e))
            }
            _ => ("ok", ops.group_of(r.author, e)),
        };
        Some(serde_json::json!({
            "id": id,
            "status": status_override.unwrap_or(status),
            "group": group.iter().map(claim::b32).collect::<Vec<_>>(),
        }))
    });
    serde_json::json!({
        "schema": "vox.room.row/1",
        "room": room_key,
        "entry_hash": claim::b32(&r.entry_hash),
        "author": claim::b32(&r.author),
        "created_millis": r.created_millis,
        "text": r.text,
        "envelope": envelope,
        "parse_error": parse_error,
        "op": op,
    })
    .to_string()
}

/// Where in the timeline `cursor` sits, or a refusal: an unknown cursor is never
/// silently treated as "from the beginning", which would re-deliver or skip without
/// anyone knowing.
fn after_cursor(
    rows: &[vox_core::node::api::MessageRow],
    cursor: Option<Digest32>,
) -> Result<usize, AppError> {
    match cursor {
        None => Ok(0),
        Some(c) => rows
            .iter()
            .position(|r| r.entry_hash == c)
            .map(|i| i + 1)
            .ok_or_else(|| {
                AppError::Usage(format!("cursor {} is not in this room's timeline", id(&c)))
            }),
    }
}

/// One row as `vox room read` and `tail` print it: `<entry-hash> <author-prefix> <text>`.
///
/// **No message can forge a row** (PRD-001 R19). A row starts at the beginning of a line,
/// so a message carrying a newline followed by `<hash> <author> …` would otherwise print a
/// second row attributed to someone else — and agents read this output. Every continuation
/// line is therefore indented with `  | `, which no row begins with, and every other
/// control character (a carriage return, an escape sequence) is shown escaped rather than
/// passed to the terminal. `--json` needs none of this: each row is one JSON-escaped line.
fn plain_row(r: &vox_core::node::api::MessageRow) -> String {
    let mut text = String::with_capacity(r.text.len());
    for c in r.text.chars() {
        match c {
            '\n' => text.push_str("\n  | "),
            '\t' => text.push('\t'),
            c if c.is_control() => text.push_str(&c.escape_unicode().to_string()),
            c => text.push(c),
        }
    }
    format!("{} {} {}", id(&r.entry_hash), short(&r.author), text)
}

/// `vox room read` — the room's messages, optionally only what follows a cursor.
///
/// Each line is `<entry-hash> <author-prefix> <text>`; with `--json`, one
/// `vox.room.row/1` object per line. The entry hash **is** the cursor.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or the cursor is not in it.
pub async fn read(
    paths: &Paths,
    room: &str,
    since: Option<&str>,
    limit: u64,
    json: bool,
) -> Result<(), AppError> {
    let (mut client, channel_id, room_key) = open_room(paths, room).await?;
    let since = match since {
        None => None,
        Some(s) => Some(parse_cursor(s)?),
    };
    if !json {
        let rows = coord::read_all(&mut client, channel_id, since).await?;
        let mut out = std::io::stdout().lock();
        let take = if limit == 0 {
            rows.len()
        } else {
            usize::try_from(limit).unwrap_or(usize::MAX)
        };
        for r in rows.iter().take(take) {
            let _ = writeln!(out, "{}", plain_row(r));
        }
        return Ok(());
    }
    // The operation index needs the whole room, not only what follows the cursor: an
    // entry after it may repeat, or conflict with, one before it.
    let all = coord::read_all(&mut client, channel_id, None).await?;
    let from = after_cursor(&all, since)?;
    let mut ops = vox_agentcomms::ops::OpIndex::new();
    for p in coord::posted_of(&all) {
        ops.insert(p.entry_hash, p.author, p.created_millis, &p.envelope);
    }
    let take = if limit == 0 {
        usize::MAX
    } else {
        usize::try_from(limit).unwrap_or(usize::MAX)
    };
    let mut out = std::io::stdout().lock();
    for r in all[from..].iter().take(take) {
        let _ = writeln!(out, "{}", row_json(&room_key, r, &ops, None));
    }
    Ok(())
}

/// `vox room roster` — who is in the room.
///
/// # Errors
/// If the node cannot be reached or the room is unknown.
pub async fn roster(paths: &Paths, room: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client.request(&Request::Roster { channel_id }).await {
        Ok(Frame::Members { members }) => {
            for m in members {
                println!("{}", id(&m));
            }
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room tail` — every row after a cursor, then every row as it lands, **with no
/// gap across a lag or a restart** (ADR-021 §7).
///
/// How the gap is closed: subscribe **first**, then read from the cursor, then emit
/// the read rows followed by the live ones, dropping any entry already emitted. A row
/// that lands between the subscription and the read arrives twice and is emitted once;
/// a row cannot land in neither. On `Lagged` — the node dropped events for this
/// subscriber — re-read from the last emitted entry rather than trusting the stream.
///
/// Duplicates across a *restart* are permitted and gaps are not: the caller persists
/// its cursor after processing, and resumes from it.
///
/// With `--json`, rows are `vox.room.row/1`, and an arrival that turns an operation
/// into a conflict re-emits every earlier row of that operation with `conflict`, so a
/// consumer learns of the change from the stream alone.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or the cursor is not in it.
pub async fn tail(
    paths: &Paths,
    room: &str,
    since: Option<&str>,
    json: bool,
) -> Result<(), AppError> {
    let (mut lookup, channel_id, room_key) = open_room(paths, room).await?;
    let cursor = match since {
        None => None,
        Some(s) => Some(parse_cursor(s)?),
    };

    // Subscribe BEFORE reading. Subscribing is terminal for a connection, so the
    // stream gets a connection of its own and `lookup` keeps answering reads.
    let mut stream = attach(paths).await?;
    stream
        .subscribe()
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?;

    let all = coord::read_all(&mut lookup, channel_id, None).await?;
    // With no cursor, a tail starts at the live edge, as it always has; everything
    // already in the room is context for the operation index, not output.
    let from = match cursor {
        None => all.len(),
        Some(_) => after_cursor(&all, cursor)?,
    };

    let mut ops = vox_agentcomms::ops::OpIndex::new();
    let mut seen: std::collections::HashSet<Digest32> = std::collections::HashSet::new();
    let mut by_hash: std::collections::HashMap<Digest32, vox_core::node::api::MessageRow> =
        std::collections::HashMap::new();
    let mut last: Option<Digest32> = None;
    let mut out = std::io::stdout().lock();

    // Index everything, emit only what follows the cursor.
    for (i, r) in all.iter().enumerate() {
        seen.insert(r.entry_hash);
        by_hash.insert(r.entry_hash, r.clone());
        if let Ok(e) = Envelope::parse(&r.text) {
            ops.insert(r.entry_hash, r.author, r.created_millis, &e);
        }
        if i >= from {
            emit_row(&mut out, &room_key, r, &ops, json, None);
        }
        last = Some(r.entry_hash);
    }

    let mut deliver = |r: vox_core::node::api::MessageRow,
                       out: &mut std::io::StdoutLock<'_>,
                       ops: &mut vox_agentcomms::ops::OpIndex,
                       last: &mut Option<Digest32>| {
        if !seen.insert(r.entry_hash) {
            return;
        }
        let mut newly_conflicted = false;
        let parsed = Envelope::parse(&r.text).ok();
        if let Some(e) = &parsed {
            newly_conflicted = ops.insert(r.entry_hash, r.author, r.created_millis, e);
        }
        by_hash.insert(r.entry_hash, r.clone());
        emit_row(out, &room_key, &r, ops, json, None);
        if newly_conflicted && json {
            if let Some(e) = &parsed {
                for earlier in ops.group_of(r.author, e) {
                    if earlier == r.entry_hash {
                        continue;
                    }
                    if let Some(row) = by_hash.get(&earlier) {
                        emit_row(out, &room_key, row, ops, json, Some("conflict"));
                    }
                }
            }
        }
        *last = Some(r.entry_hash);
    };

    // **An event is a wake, never the data** (ADR-020 §6). Only this node's own posts
    // arrive as `NewEntry`; an entry that arrives from another member by sync is
    // announced as `Synced`, and one that becomes readable when a sender key arrives as
    // `SenderKeyReceived` — neither carries the row. So on any of them, and on
    // `Lagged`, the room is re-read and whatever this stream has not emitted is emitted.
    // A full re-read rather than `since <last>`, because an entry rendered late (its key
    // arrived after it did) is not guaranteed to sit after the last one emitted.
    loop {
        let reread = match stream.next().await {
            Ok(Some(Frame::Event(vox_core::node::api::NodeEvent::NewEntry {
                channel_id: c,
                row,
            }))) if c == channel_id => {
                deliver(row, &mut out, &mut ops, &mut last);
                false
            }
            Ok(Some(Frame::Event(
                vox_core::node::api::NodeEvent::Synced { channel_id: c, .. }
                | vox_core::node::api::NodeEvent::SenderKeyReceived { channel_id: c, .. },
            ))) => c == channel_id,
            Ok(Some(Frame::Lagged { missed })) => {
                eprintln!("vox: this stream fell behind by {missed} events; re-reading the room");
                true
            }
            Ok(Some(_)) => false,
            Ok(None) => return Ok(()), // the node stopped
            Err(e) => return Err(AppError::Usage(e.to_string())),
        };
        if reread {
            for r in coord::read_all(&mut lookup, channel_id, None).await? {
                deliver(r, &mut out, &mut ops, &mut last);
            }
        }
    }
}

fn emit_row(
    out: &mut std::io::StdoutLock<'_>,
    room_key: &str,
    r: &vox_core::node::api::MessageRow,
    ops: &vox_agentcomms::ops::OpIndex,
    json: bool,
    status: Option<&str>,
) {
    let line = if json {
        row_json(room_key, r, ops, status)
    } else {
        plain_row(r)
    };
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Parse a full entry hash, in the same base32 the first column prints.
///
/// Deliberately **not** prefix-matched, unlike a room id. A cursor is copied from
/// a previous line of output rather than retyped by a person, and a prefix that
/// matched the wrong entry would silently skip or repeat messages — the failure
/// an agent could not detect.
fn parse_cursor(s: &str) -> Result<Digest32, AppError> {
    let t = s.trim();
    if t.len() != B32_DIGEST_LEN {
        return Err(AppError::Usage(format!(
            "--since takes a full {B32_DIGEST_LEN}-character entry hash, as \
             `vox room read` prints it in the first column"
        )));
    }
    b32_decode(t, "entry hash").map_err(|_| {
        AppError::Usage(format!(
            "--since is not an entry hash; it should be the {B32_DIGEST_LEN} \
             characters in the first column of `vox room read`"
        ))
    })
}

// ---------------------------------------------------------------------------
// Live coordination claims (ADR-020 §5, as corrected by ADR-021 §4–§6)
// ---------------------------------------------------------------------------
//
// Claims are **messages, not locks**. Nothing here reserves anything in the node:
// the state is whatever `claim::fold` computes from the room's log, so two workers
// on one version converge on the same answer without either asking a coordinator.
//
// What ADR-021 changed, and why each verb now carries so much:
//
// - **the owner is `(author, session)`** — two sessions on one harness are two owners,
//   so every verb needs a session and refuses without one;
// - **every operation is stamped with this binary's version** and a worker refuses to
//   coordinate at all while any participant runs another — exit 3, naming it;
// - **every operation carries an operation id**, so a retry is one operation and a
//   conflicting reuse is explicit — exit 4;
// - **a handoff names a fingerprint**, never a petname a reader resolves differently,
//   and leaves the resource *pending* until an eligible session claims it.
//
// None of this is work tracking. `--work` is carried opaquely for a tracker that owns
// the work (ADR-021 §1); nothing here reads it.

use vox_agentcomms::claim::{self, Outcome, Owner, Posted, State};
use vox_agentcomms::envelope::Envelope;

use crate::coord::{self, Draft};

/// Options every coordinating verb shares.
#[derive(Debug, Clone, Default)]
pub struct CoordOpts {
    /// The session to act as, overriding the environment.
    pub session: Option<String>,
    /// The operation id to post under — pass the same one on every retry.
    pub op: Option<String>,
    /// Print one JSON object instead of prose.
    pub json: bool,
}

/// Attach to the node and resolve the room: the client, the room's id and its key.
async fn open_room(paths: &Paths, room: &str) -> Result<(IpcClient, Digest32, String), AppError> {
    let mut client = attach(paths).await?;
    let cid = room_of(&mut client, room).await?;
    Ok((client, cid, id(&cid)))
}

/// What one coordinating verb did: the post, what it did in the fold, and who asked.
struct Done {
    posting: coord::Posting,
    outcome: Option<Outcome>,
    session: String,
    room: String,
}

/// Run one claim-protocol operation end to end: session, version gate, post exactly
/// once in effect, read back, and what it did.
async fn run_op(
    paths: &Paths,
    room: &str,
    opts: &CoordOpts,
    kind: &str,
    data: serde_json::Map<String, serde_json::Value>,
    body: String,
) -> Result<Done, AppError> {
    let session = coord::require_session(opts.session.as_deref())?;
    let op = match &opts.op {
        Some(op) if vox_agentcomms::ops::is_valid_op(op) => op.clone(),
        Some(op) => {
            return Err(AppError::Usage(format!(
                "--op {op:?} is not an operation id: use 8–64 of [A-Za-z0-9._-]"
            )))
        }
        None => coord::new_op()?,
    };
    let (mut client, cid, room_key) = open_room(paths, room).await?;
    let snap = coord::participate(&mut client, cid, &room_key, &session).await?;
    let draft = Draft {
        kind: kind.into(),
        body,
        data,
        ..Draft::default()
    };
    let posting = coord::post_once(&mut client, cid, &draft, &session, &op, &snap).await?;
    let outcome = posting
        .after
        .fold
        .outcomes
        .get(&posting.entry_hash)
        .cloned();
    Ok(Done {
        posting,
        outcome,
        session,
        room: room_key,
    })
}

fn millis_as_time(ms: u64) -> String {
    held_since(ms / 1_000)
}

/// One resource's state as JSON — the shape `board --json` and every verb's `--json`
/// share, so a consumer parses one thing.
fn state_json(resource: &str, s: &State, me: &Owner) -> serde_json::Value {
    match s {
        State::Held {
            owner,
            acquisition,
            since_millis,
            ttl_secs,
            expires_millis,
        } => serde_json::json!({
            "resource": resource,
            "state": "held",
            "owner_fp": claim::b32(&owner.author),
            "owner_session": owner.session,
            "acquisition": claim::b32(acquisition),
            "since_millis": since_millis,
            "ttl_secs": ttl_secs,
            "expires_millis": expires_millis,
            "mine": owner == me,
        }),
        State::Pending {
            from,
            to_fp,
            to_session,
            to_name,
            handoff,
            since_millis,
            deadline_millis,
        } => serde_json::json!({
            "resource": resource,
            "state": "pending",
            "from_fp": claim::b32(&from.author),
            "from_session": from.session,
            "to_fp": claim::b32(to_fp),
            "to_session": to_session,
            "to_name": to_name,
            "handoff": claim::b32(handoff),
            "since_millis": since_millis,
            "deadline_millis": deadline_millis,
            "eligible": s.is_eligible(me),
        }),
    }
}

fn outcome_json(o: Option<&Outcome>) -> serde_json::Value {
    match o {
        None => serde_json::Value::Null,
        Some(Outcome::Applied) => "applied".into(),
        Some(Outcome::Lost) => "lost".into(),
        Some(Outcome::NoEffect(why)) => serde_json::json!({"no_effect": why}),
        Some(Outcome::Invalid(why)) => serde_json::json!({"invalid": why}),
        Some(Outcome::OtherVersion(s)) => serde_json::json!({"other_version": s.token()}),
        Some(Outcome::Duplicate { of }) => serde_json::json!({"duplicate_of": claim::b32(of)}),
        Some(Outcome::Conflict { group }) => {
            serde_json::json!({"conflict": group.iter().map(claim::b32).collect::<Vec<_>>()})
        }
    }
}

/// Report a coordinating verb: JSON for a program, a sentence for a person, and the
/// exit status that is the machine-readable half of whether it did what was asked.
fn report(
    done: &Done,
    kind: &str,
    resource: &str,
    opts: &CoordOpts,
    ok: bool,
    said: &str,
) -> Result<(), AppError> {
    let me = Owner {
        author: done.posting.after.me,
        session: done.session.clone(),
    };
    if opts.json {
        let state = done
            .posting
            .after
            .fold
            .resources
            .get(resource)
            .map(|s| state_json(resource, s, &me));
        println!(
            "{}",
            serde_json::json!({
                "schema": "vox.room.op/1",
                "room": done.room,
                "type": kind,
                "resource": resource,
                "session": done.session,
                "entry_hash": claim::b32(&done.posting.entry_hash),
                "op": done.posting.op,
                "status": done.posting.status,
                "outcome": outcome_json(done.outcome.as_ref()),
                "ok": ok,
                "state": state,
            })
        );
    } else if ok {
        println!("{said}");
    }
    if ok {
        Ok(())
    } else if opts.json {
        Err(AppError::Refused {
            code: 1,
            message: said.to_owned(),
        })
    } else {
        Err(AppError::Usage(said.to_owned()))
    }
}

fn who(o: &Owner) -> String {
    format!("{}/{}", &claim::b32(&o.author)[..12], o.session)
}

fn resource_of(resource: Option<&str>, work: Option<&str>) -> Result<String, AppError> {
    match (resource, work) {
        (Some(r), Some(w)) if r != w => Err(AppError::Usage(format!(
            "the resource {r:?} and --work {w:?} differ; a claim on a work item uses the \
             reference as its resource (ADR-021 §2)"
        ))),
        (_, Some(w)) if !vox_agentcomms::envelope::is_valid_work(w) => {
            Err(AppError::Usage(format!(
                "--work {w:?} is not a work reference: use <scheme>:<id>, the scheme \
                 [a-z][a-z0-9-]{{0,15}} and the id 1–{} of [A-Za-z0-9._~/#:-] (ADR-021 §3)",
                vox_agentcomms::envelope::MAX_WORK_ID
            )))
        }
        (Some(r), _) | (None, Some(r)) if !r.trim().is_empty() => Ok(r.to_owned()),
        _ => Err(AppError::Usage("name a resource, or pass --work".into())),
    }
}

/// `vox room claim` — take a resource, or complete a handoff pending for this session.
///
/// # Errors
/// Exit 1 if somebody else holds it, 3 on a version refusal, 4 on an op conflict.
pub async fn claim_resource(
    paths: &Paths,
    room: &str,
    resource: Option<&str>,
    work: Option<&str>,
    ttl_secs: Option<u64>,
    opts: &CoordOpts,
) -> Result<(), AppError> {
    let resource = resource_of(resource, work)?;
    let mut data = serde_json::Map::new();
    data.insert("resource".into(), resource.clone().into());
    if let Some(w) = work {
        data.insert(vox_agentcomms::envelope::WORK_KEY.into(), w.into());
    }
    if let Some(t) = ttl_secs {
        data.insert("ttl_secs".into(), t.into());
    }
    let done = run_op(
        paths,
        room,
        opts,
        claim::CLAIM,
        data,
        format!("claiming {resource}"),
    )
    .await?;
    let me = Owner {
        author: done.posting.after.me,
        session: done.session.clone(),
    };
    // **Say whether it was won.** A claim is a message, not a lock: an earlier claim
    // beats this one, and an agent that cannot tell would start work somebody else is
    // already doing. The current state is the answer, not this post's own outcome —
    // on a retry the resource may have moved on since the first attempt.
    let (ok, said) = match done.posting.after.fold.resources.get(&resource) {
        Some(State::Held { owner, .. }) if *owner == me => (true, format!("you hold {resource}")),
        Some(State::Held {
            owner,
            since_millis,
            ..
        }) => (
            false,
            format!(
                "{resource} is held by {} since {} — you did not get it",
                who(owner),
                millis_as_time(*since_millis)
            ),
        ),
        Some(State::Pending {
            to_fp, to_session, ..
        }) => (
            false,
            format!(
                "{resource} is reserved by a handoff for {}{} — you did not get it",
                &claim::b32(to_fp)[..12],
                to_session
                    .as_ref()
                    .map(|s| format!("/{s}"))
                    .unwrap_or_default()
            ),
        ),
        None => (
            false,
            format!(
                "{resource} is not held by anyone, including you — the claim has not \
                 converged yet; run `vox room board {room}` to check"
            ),
        ),
    };
    report(&done, claim::CLAIM, &resource, opts, ok, &said)
}

/// `vox room release` — give a resource up. Only the exact holding session's release
/// counts, and releasing means neither done nor failed (ADR-021 §3).
///
/// # Errors
/// Exit 1 if this session did not hold it, 3 on a version refusal, 4 on an op conflict.
pub async fn release_resource(
    paths: &Paths,
    room: &str,
    resource: &str,
    opts: &CoordOpts,
) -> Result<(), AppError> {
    if resource.trim().is_empty() {
        return Err(AppError::Usage("a release needs a resource".into()));
    }
    let mut data = serde_json::Map::new();
    data.insert("resource".into(), resource.into());
    let done = run_op(
        paths,
        room,
        opts,
        claim::RELEASE,
        data,
        format!("releasing {resource}"),
    )
    .await?;
    let (ok, said) = match &done.outcome {
        Some(Outcome::Applied) => (true, format!("released {resource}")),
        Some(Outcome::NoEffect(why)) => (false, format!("{resource} was not released: {why}")),
        other => (false, format!("{resource} was not released: {other:?}")),
    };
    report(&done, claim::RELEASE, resource, opts, ok, &said)
}

/// `vox room handoff` — relinquish a resource and reserve it for another harness,
/// named by fingerprint (a unique prefix of a room member's), and optionally one exact
/// session of it.
///
/// # Errors
/// Exit 1 if this session does not hold it, 3 on a version refusal, 4 on a conflict.
#[allow(clippy::too_many_arguments)]
pub async fn handoff_resource(
    paths: &Paths,
    room: &str,
    resource: &str,
    to: &str,
    to_session: Option<&str>,
    ttl_secs: Option<u64>,
    opts: &CoordOpts,
) -> Result<(), AppError> {
    if resource.trim().is_empty() {
        return Err(AppError::Usage("a handoff needs a resource".into()));
    }
    // Resolve the recipient **here, once, by the sender**, to a full fingerprint. A
    // petname is local to whoever typed it, so a handoff that named one would resolve
    // to different owners on different nodes (ADR-021 F2).
    let to_fp = {
        let (mut client, cid, _) = open_room(paths, room).await?;
        let members = match client.request(&Request::Roster { channel_id: cid }).await {
            Ok(Frame::Members { members }) => members,
            Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
            Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
            Err(e) => return Err(AppError::Usage(e.to_string())),
        };
        resolve_prefix(to, &members).map_err(|e| {
            AppError::Usage(format!(
                "--to names a room member by fingerprint (a unique prefix of one in \
                 `vox room roster`): {e}"
            ))
        })?
    };
    let ttl = ttl_secs.unwrap_or(claim::DEFAULT_HANDOFF_TTL_SECS);
    if ttl == 0 {
        return Err(AppError::Usage(
            "--ttl 0 would make a handoff that is over before it begins".into(),
        ));
    }
    let mut data = serde_json::Map::new();
    data.insert("resource".into(), resource.into());
    data.insert("to_fp".into(), claim::b32(&to_fp).into());
    data.insert("to".into(), to.into());
    data.insert("ttl_secs".into(), ttl.into());
    if let Some(s) = to_session.filter(|s| !s.is_empty()) {
        data.insert("to_session".into(), s.into());
    }
    let done = run_op(
        paths,
        room,
        opts,
        claim::HANDOFF,
        data,
        format!("handing {resource} to {}", &claim::b32(&to_fp)[..12]),
    )
    .await?;
    let (ok, said) = match (&done.outcome, done.posting.after.fold.resources.get(resource)) {
        (Some(Outcome::Applied), Some(State::Pending { deadline_millis, .. })) => (
            true,
            format!(
                "{resource} is reserved for {}{} until {}; it completes when that session claims it",
                &claim::b32(&to_fp)[..12],
                to_session.map(|s| format!("/{s}")).unwrap_or_default(),
                millis_as_time(*deadline_millis)
            ),
        ),
        (Some(Outcome::Applied), _) => (true, format!("{resource} was handed off and has since moved on")),
        (Some(Outcome::NoEffect(why)), _) => (false, format!("{resource} was not handed off: {why}")),
        (other, _) => (false, format!("{resource} was not handed off: {other:?}")),
    };
    report(&done, claim::HANDOFF, resource, opts, ok, &said)
}

/// `vox room decline` — refuse a handoff pending for this session. The resource is
/// **freed**, not returned to the sender.
///
/// # Errors
/// Exit 1 if no handoff is pending for this session, 3 or 4 as the other verbs.
pub async fn decline_resource(
    paths: &Paths,
    room: &str,
    resource: &str,
    opts: &CoordOpts,
) -> Result<(), AppError> {
    let mut data = serde_json::Map::new();
    data.insert("resource".into(), resource.into());
    let done = run_op(
        paths,
        room,
        opts,
        vox_agentcomms::envelope::work::DECLINE,
        data,
        format!("declining the handoff of {resource}"),
    )
    .await?;
    let (ok, said) = match &done.outcome {
        Some(Outcome::Applied) => (true, format!("declined {resource}; it is free")),
        Some(Outcome::NoEffect(why)) => (false, format!("{resource} was not declined: {why}")),
        other => (false, format!("{resource} was not declined: {other:?}")),
    };
    report(
        &done,
        vox_agentcomms::envelope::work::DECLINE,
        resource,
        opts,
        ok,
        &said,
    )
}

/// `vox room renew` — extend this session's current holding of a resource.
///
/// The renewal names the acquisition it extends, read from the board at the moment of
/// asking, so a renewal that arrives late cannot revive an expired holding or extend
/// a later one (ADR-021 §4).
///
/// # Errors
/// Exit 1 if this session does not hold it, 3 or 4 as the other verbs.
pub async fn renew_resource(
    paths: &Paths,
    room: &str,
    resource: &str,
    opts: &CoordOpts,
) -> Result<(), AppError> {
    let session = coord::require_session(opts.session.as_deref())?;
    let acquisition = {
        let (mut client, cid, _) = open_room(paths, room).await?;
        let snap = coord::snapshot(&mut client, cid).await?;
        let me = Owner {
            author: snap.me,
            session: session.clone(),
        };
        match snap.fold.resources.get(resource) {
            Some(State::Held {
                owner, acquisition, ..
            }) if *owner == me => *acquisition,
            _ => {
                return Err(AppError::Usage(format!(
                    "this session ({session}) does not hold {resource}, so there is \
                     nothing to renew"
                )))
            }
        }
    };
    let mut data = serde_json::Map::new();
    data.insert("resource".into(), resource.into());
    data.insert("acquisition".into(), claim::b32(&acquisition).into());
    let done = run_op(
        paths,
        room,
        opts,
        claim::RENEW,
        data,
        format!("renewing {resource}"),
    )
    .await?;
    let (ok, said) = match (
        &done.outcome,
        done.posting.after.fold.resources.get(resource),
    ) {
        (
            Some(Outcome::Applied),
            Some(State::Held {
                expires_millis: Some(e),
                ..
            }),
        ) => (
            true,
            format!("renewed {resource} until {}", millis_as_time(*e)),
        ),
        (Some(Outcome::NoEffect(why)), _) => (false, format!("{resource} was not renewed: {why}")),
        (other, _) => (false, format!("{resource} was not renewed: {other:?}")),
    };
    report(&done, claim::RENEW, resource, opts, ok, &said)
}

/// `vox room board` — what is held or pending, by whom, until when; whether
/// coordination is allowed at all; and every operation that had no effect and why.
///
/// A pure function of the log under this version, so every worker on it computes the
/// same board.
///
/// # Errors
/// If the node cannot be reached or the room is unknown.
pub async fn board(
    paths: &Paths,
    room: &str,
    json: bool,
    session: Option<&str>,
) -> Result<(), AppError> {
    let (mut client, cid, room_key) = open_room(paths, room).await?;
    let snap = coord::snapshot(&mut client, cid).await?;
    let session = coord::session(session).unwrap_or_default();
    let me = Owner {
        author: snap.me,
        session: session.clone(),
    };

    if json {
        let resources: Vec<serde_json::Value> = snap
            .fold
            .resources
            .iter()
            .map(|(r, s)| state_json(r, s, &me))
            .collect();
        let by_hash: std::collections::BTreeMap<[u8; 32], &Posted> =
            snap.posted.iter().map(|p| (p.entry_hash, p)).collect();
        let violations: Vec<serde_json::Value> = snap
            .fold
            .outcomes
            .iter()
            .filter(|(_, o)| !matches!(o, Outcome::Applied | Outcome::Lost))
            .map(|(h, o)| {
                let p = by_hash.get(h);
                serde_json::json!({
                    "entry_hash": claim::b32(h),
                    "author": p.map(|p| claim::b32(&p.author)),
                    "session": p.map(|p| p.envelope.from.clone()),
                    "type": p.map(|p| p.envelope.kind.clone()),
                    "outcome": outcome_json(Some(o)),
                })
            })
            .collect();
        let participants: Vec<serde_json::Value> = snap
            .table
            .participants
            .iter()
            .map(|p| {
                serde_json::json!({
                    "author": claim::b32(&p.author),
                    "session": p.session,
                    "stamp": p.stamp.token(),
                    "version": p.stamp.carried(&snap.table.mine),
                    "last_millis": p.last_millis,
                    "entry_hash": claim::b32(&p.entry_hash),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "schema": "vox.room.board/1",
                "room": room_key,
                "me": { "author": claim::b32(&snap.me), "session": session },
                "version": coord::VERSION,
                "coordination": if snap.table.refused() { "refused" } else { "ok" },
                "participants": participants,
                "resources": resources,
                "violations": violations,
                "position": {
                    "entries": snap.rows.len(),
                    "last": snap.rows.last().map(|r| claim::b32(&r.entry_hash)),
                },
                "now_millis": snap.now_millis,
            })
        );
        return Ok(());
    }

    let mut out = std::io::stdout().lock();
    if snap.table.refused() {
        writeln!(out, "{}", coord::refusal(&room_key, &snap.table)).map_err(AppError::Io)?;
    }
    if snap.fold.resources.is_empty() {
        writeln!(out, "nothing is claimed").map_err(AppError::Io)?;
        return Ok(());
    }
    for (resource, s) in &snap.fold.resources {
        let line = match s {
            State::Held {
                owner,
                expires_millis,
                ..
            } => {
                let mine = if *owner == me { " (you)" } else { "" };
                let expiry = match expires_millis {
                    // Time remaining, not an absolute time: "in 240s" is actionable.
                    Some(e) if *e > snap.now_millis => {
                        format!(" expires in {}s", (e - snap.now_millis).div_ceil(1_000))
                    }
                    Some(_) => " expired".to_owned(),
                    None => String::new(),
                };
                format!("{resource}\t{}{mine}{expiry}", who(owner))
            }
            State::Pending {
                from,
                to_fp,
                to_session,
                deadline_millis,
                ..
            } => format!(
                "{resource}\tpending handoff from {} to {}{}{} (lapses in {}s)",
                who(from),
                &claim::b32(to_fp)[..12],
                to_session
                    .as_ref()
                    .map(|s| format!("/{s}"))
                    .unwrap_or_default(),
                if s.is_eligible(&me) {
                    " — you may claim or decline it"
                } else {
                    ""
                },
                deadline_millis
                    .saturating_sub(snap.now_millis)
                    .div_ceil(1_000)
            ),
        };
        writeln!(out, "{line}").map_err(AppError::Io)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// File exchange (ADR-020 §11, M19.8)
// ---------------------------------------------------------------------------
//
// **The bytes never enter the log.** They ride a room-bound service — the same
// ADR-013/017 machinery `vox serve` uses — and what goes on the log is a signed
// announcement naming the file, its size and its **SHA-256**. That is the decider's
// own idiom, `nc -l` one side and `cat file | nc` the other, with the address
// become a `.vox` name: no routable address, no firewall hole, no VPN, and the
// bytes end-to-end encrypted because the overlay already is.
//
// Two properties follow, and both are deliberate:
//
//   - the **announcement is durable** — it is a log entry, so an agent asleep when
//     the file was offered still sees it on waking;
//   - the **bytes are live** — the sender must still be serving, so a late
//     collector may find the offer gone. It is then told so, which is better than a
//     reference that silently resolves to nothing.
//
// **Nobody is granted anything.** Reach is gated on the offering node's trust
// keyring plus room authorship, and reading the announcement requires exactly the
// same ring entry — so the audience of the announcement *is* the audience of the
// transfer, by construction rather than by coincidence.
//
// The hash earns its place for a reason unrelated to secrecy: `cat | nc` **truncates
// silently**. The connection drops, the receiver gets a partial file, and `nc` exits
// 0. Verifying against a hash the sender signed turns that into a loud failure.

/// The envelope type an offer is announced with.
const FILE: &str = "file";

/// Read a file and return its SHA-256 and length.
fn digest_file(path: &std::path::Path) -> Result<(String, u64), AppError> {
    use sha2::{Digest as _, Sha256};
    let mut f = std::fs::File::open(path)
        .map_err(|e| AppError::Usage(format!("opening {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = std::io::Read::read(&mut f, &mut buf)
            .map_err(|e| AppError::Usage(format!("reading {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex(&hasher.finalize()), total))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// `vox room send` — offer a file to a room and announce it.
///
/// Runs until interrupted: the bytes are served live, so stopping this stops the
/// offer. Every member that collects it gets the same file.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, the file cannot be read, or
/// the node refuses to offer the service.
pub async fn send_file(paths: &Paths, room: &str, path: &std::path::Path) -> Result<(), AppError> {
    let (sha256, size) = digest_file(path)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_owned());
    // The tag is derived from the content, so two offers of the same bytes collide
    // harmlessly and two different files never do.
    let tag = format!("file-{}", &sha256[..16]);

    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;

    // A listener that hands the file to whoever connects, for as long as we run.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| AppError::Usage(format!("cannot listen locally: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| AppError::Usage(format!("cannot read the local address: {e}")))?;

    match client
        .request(&Request::AddService {
            channel_id,
            service_tag: tag.clone(),
            local: local.to_string(),
        })
        .await
    {
        Ok(Frame::Ok) => {}
        Ok(Frame::Error { reason }) => {
            // Not "needs bind:<tag>, which the room's admin grants": that capability was
            // deleted in ADR-017's third revision — offering a port of your own machine
            // is not the room's business — and `add_service` stopped checking it at M17.7.
            // The message named a permission nobody can hold and an admin nobody has.
            return Err(AppError::Usage(format!("cannot offer {tag:?}: {reason}")));
        }
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    }

    // A `dial:` grant per member used to be issued here, "so it works under either
    // model". There is one model: reach is the host's trust keyring (M17.7), and the
    // capability has not been consulted since. The loop wrote a governance fact per
    // member per offer onto the room's log, which nothing read — and it kept the
    // withdrawn model alive in the one verb a person uses most.

    let env = {
        let mut e = Envelope::new(FILE, &format!("offering {name} ({size} bytes)"));
        e.data = serde_json::json!({
            "name": name,
            "size": size,
            "sha256": sha256,
            "tag": tag,
        });
        e
    };
    post(paths, room, Some(&env.to_text())).await?;

    println!("vox: offering {name} ({size} bytes) as {tag}");
    println!("     sha256 {sha256}");
    println!(
        "     collect it with: vox room get {} {name}",
        &room_of_label(channel_id)
    );
    println!("     Ctrl-C stops the offer; the announcement stays on the log");

    let path = path.to_owned();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((mut sock, _)) = accepted else { continue };
                let p = path.clone();
                // `std::fs` because this workspace's tokio has no `fs` feature, and
                // widening a dependency for one CLI verb is the wrong trade. The
                // reads are chunked, so a large file is not held in memory.
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt as _;
                    let Ok(mut f) = std::fs::File::open(&p) else { return };
                    let mut buf = vec![0u8; 64 * 1024];
                    loop {
                        match std::io::Read::read(&mut f, &mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = sock.flush().await;
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    println!("vox: no longer offering {tag}");
    let _ = client
        .request(&Request::RemoveService {
            channel_id,
            service_tag: tag,
        })
        .await;
    Ok(())
}

fn room_of_label(channel_id: Digest32) -> String {
    b32_encode(&channel_id).chars().take(12).collect()
}

/// An offer read off the room's log.
struct Offer {
    author: Digest32,
    name: String,
    size: u64,
    sha256: String,
    tag: String,
}

/// `vox room get` — collect an offered file and verify it.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, no matching offer exists,
/// the transfer cannot be established, or **the bytes do not match the announced
/// hash**, in which case the partial file is removed.
pub async fn get_file(
    paths: &Paths,
    room: &str,
    selector: &str,
    out: Option<&std::path::Path>,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let rows = match client
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
    };

    // The most recent matching offer wins: re-offering a file supersedes.
    let offer = rows
        .iter()
        .rev()
        .filter_map(|r| {
            let env = Envelope::parse(&r.text).ok()?;
            if env.kind != FILE {
                return None;
            }
            let d = &env.data;
            let name = d.get("name")?.as_str()?.to_owned();
            let sha256 = d.get("sha256")?.as_str()?.to_owned();
            let tag = d.get("tag")?.as_str()?.to_owned();
            let size = d.get("size")?.as_u64()?;
            (name == selector || sha256.starts_with(selector) || tag == selector).then_some(Offer {
                author: r.author,
                name,
                size,
                sha256,
                tag,
            })
        })
        .next()
        .ok_or_else(|| {
            AppError::Usage(format!(
                "no offer in this room matches {selector:?} — `vox room read` shows what was \
                 announced"
            ))
        })?;

    let dest = out.map_or_else(|| std::path::PathBuf::from(&offer.name), Path::to_owned);

    let bound = match client
        .request(&Request::Forward {
            channel_id,
            host: offer.author,
            service_tag: offer.tag.clone(),
            local: "127.0.0.1:0".into(),
        })
        .await
    {
        Ok(Frame::Bound { local }) => local,
        Ok(Frame::Error { reason }) => {
            return Err(AppError::Usage(format!(
                "cannot reach the offer: {reason} — the sender may have stopped serving it, or \
                 may not have trusted this identity"
            )))
        }
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };

    let result = collect(&bound, &dest, &offer).await;
    let _ = client
        .request(&Request::StopForward {
            local: bound.clone(),
        })
        .await;
    result
}

/// Stream the offered bytes to `dest`, verifying as we go.
async fn collect(bound: &str, dest: &std::path::Path, offer: &Offer) -> Result<(), AppError> {
    use sha2::{Digest as _, Sha256};
    use tokio::io::AsyncReadExt as _;

    let mut sock = tokio::net::TcpStream::connect(bound)
        .await
        .map_err(|e| AppError::Usage(format!("connecting to the forward: {e}")))?;
    let mut file = std::fs::File::create(dest)
        .map_err(|e| AppError::Usage(format!("creating {}: {e}", dest.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = sock
            .read(&mut buf)
            .await
            .map_err(|e| AppError::Usage(format!("reading the transfer: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        std::io::Write::write_all(&mut file, &buf[..n])
            .map_err(|e| AppError::Usage(format!("writing {}: {e}", dest.display())))?;
        total += n as u64;
    }
    std::io::Write::flush(&mut file)
        .map_err(|e| AppError::Usage(format!("flushing {}: {e}", dest.display())))?;
    drop(file);

    let got = hex(&hasher.finalize());
    if got != offer.sha256 {
        // **The partial file is removed.** `cat | nc` truncating silently is the
        // classic way this idiom bites; leaving a file that looks complete and is
        // not would reproduce exactly that failure with extra steps.
        let _ = std::fs::remove_file(dest);
        return Err(AppError::Usage(format!(
            "the transfer does not match what was announced — expected sha256 {} over {} bytes, \
             got {got} over {total}. The partial file was removed.",
            offer.sha256, offer.size
        )));
    }
    println!("vox: {} ({total} bytes) verified", dest.display());
    Ok(())
}

/// Read a passphrase from stdin, stripping exactly one trailing newline.
///
/// Stdin rather than an argument: argv is visible to anything that can run `ps`.
fn passphrase_from_stdin(what: &str) -> Result<String, AppError> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| AppError::Usage(format!("reading {what} on stdin: {e}")))?;
    let p = buf
        .strip_suffix('\n')
        .unwrap_or(&buf)
        .strip_suffix('\r')
        .unwrap_or_else(|| buf.strip_suffix('\n').unwrap_or(&buf));
    if p.is_empty() {
        // The caller's phrase is a noun phrase ("the room's passphrase", "a passphrase
        // for the new room"), so it reads as "expected <phrase> on stdin" and never as
        // "no a passphrase", which is what "no {what}" produced.
        return Err(AppError::Usage(format!(
            "expected {what} on stdin — pipe it in, e.g. `echo … | vox room join …`"
        )));
    }
    Ok(p.to_owned())
}

/// `vox room join` — join a room over a running node (ADR-020 §12).
///
/// This is what makes agent comms reachable on a host with no terminal. `vox
/// daemon` lets a node *hold* rooms unattended; until this existed, the only way
/// to get a room onto that node was the TUI, so an agent on a remote machine could
/// run a daemon and never have anything to put in it.
///
/// # Errors
/// If the node cannot be reached, or the join is refused — and the refusal is
/// reported as the node gave it, because `Unreachable` and a wrong passphrase need
/// completely different responses from whoever holds the link.
pub async fn join(paths: &Paths, link: &str, local_name: &str) -> Result<(), AppError> {
    let passphrase = passphrase_from_stdin("the room's passphrase")?;
    let mut client = attach(paths).await?;
    match client
        .request(&Request::Join {
            link: link.to_owned(),
            local_name: local_name.to_owned(),
            passphrase,
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: joined {local_name}");
            println!("     you can read this room; whether anyone can read YOU is their decision");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(format!("cannot join: {reason}"))),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room create` — create a room over a running node.
///
/// # Errors
/// If the node cannot be reached or the create is refused.
pub async fn create(paths: &Paths, local_name: &str) -> Result<(), AppError> {
    let passphrase = passphrase_from_stdin("a passphrase for the new room")?;
    let mut client = attach(paths).await?;
    match client
        .request(&Request::Create {
            local_name: local_name.to_owned(),
            passphrase,
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: created {local_name}");
            println!("     `vox room list` shows its id; that id is what agents pass as --room");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(format!("cannot create: {reason}"))),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room invite` — print a room's address for someone else to join with.
///
/// The address is rendezvous information, not a credential: it names the room and
/// where to look, it carries no passphrase, and since M17.6 joining with it grants
/// nothing. Send the passphrase by a different channel, and decide separately who
/// may read you.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or no link is minted.
pub async fn invite(paths: &Paths, room: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client.request(&Request::Invite { channel_id }).await {
        Ok(Frame::Link { url }) => {
            println!("{url}");
            eprintln!("vox: send the passphrase by a different channel than this address");
            eprintln!("     joining grants nothing — use `vox trust add` to decide who reads you");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

// ---------------------------------------------------------------- the trust keyring

/// Whether a node is already serving this profile's control socket.
///
/// Used to decide whether a verb should ask the running node or start its own. It is a
/// probe, not a guarantee: the node may stop between this answering and the request being
/// made, and the caller handles that the same way it handles any other socket failure.
pub async fn node_is_running(paths: &Paths) -> bool {
    let sock = paths.socket_file();
    sock.exists() && IpcClient::open(&sock).await.is_ok()
}

/// `vox trust add`, asked of the running node instead of a second one.
///
/// The keyring is the one thing an agent session must not be able to change (ADR-020 §7),
/// so the request carries the identity passphrase and the node checks it before doing
/// anything. That is what makes this safe to put on a socket an agent can reach.
pub async fn trust_add(
    paths: &Paths,
    target: Digest32,
    petname: &str,
    identity_passphrase: &str,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    match client
        .request(&Request::Trust {
            target,
            petname: petname.to_owned(),
            identity_passphrase: identity_passphrase.to_owned(),
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: trusting {} as {petname:?}", short(&target));
            println!("     it may now read what you write in every room you share — now and later");
            println!("     and reach every service you bind to a room you are both in");
            println!("     `vox trust remove` undoes it and changes the lock everywhere");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox trust remove`, asked of the running node.
pub async fn trust_remove(
    paths: &Paths,
    target: Digest32,
    identity_passphrase: &str,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    match client
        .request(&Request::Untrust {
            target,
            identity_passphrase: identity_passphrase.to_owned(),
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: no longer trusting {}", short(&target));
            println!("     your sender key is rotated and everyone still trusted is re-keyed");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox trust list`, asked of the running node.
pub async fn trust_list(paths: &Paths, identity_passphrase: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    match client
        .request(&Request::TrustList {
            identity_passphrase: identity_passphrase.to_owned(),
        })
        .await
    {
        Ok(Frame::Trusted { entries }) => {
            if entries.is_empty() {
                println!("no trusted identities");
                println!("     nobody can read what you write until you `vox trust add` them");
                return Ok(());
            }
            for (id, petname) in entries {
                println!("{}  {petname}", vox_core::node::link::b32_encode(&id));
            }
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox id`, asked of the running node.
///
/// Printing your own fingerprint is the most ordinary thing a person does — it is what
/// they send to somebody who will type it into `vox trust add` — and it needs no secret
/// and changes nothing. It nevertheless failed outright whenever a daemon held the
/// profile, because it went through a node of its own.
///
/// The socket's hello already carries it (protocol 2's `me`), so this costs no new
/// request and no passphrase: a fingerprint is public.
pub async fn print_identity(paths: &Paths) -> Result<(), AppError> {
    let client = attach(paths).await?;
    let Some(me) = client.me() else {
        return Err(AppError::Usage(
            "the running node has no identity yet. Make one:  vox id  (with the daemon \
             stopped)"
                .into(),
        ));
    };
    // The whole fingerprint, alone on the line, so it pipes and pastes without editing.
    println!("{}", vox_core::node::link::b32_encode(&me));
    Ok(())
}
