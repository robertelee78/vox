//! ADR-020 §8 — `vox room`: the agent-facing verbs, over an **attached** node.
//!
//! These are one-shot clients of the vox daemon (ADR-026 L-2): they never attach a node, and
//! ask as one that is already attached. That is the point: agent comms puts several agent
//! sessions on one harness node (ADR-020 §2, one identity per `(host, harness)`), so these
//! reach the daemon's socket as that node, already running and already unlocked.
//!
//! Two consequences fall out of that, both intended:
//!
//! - **No passphrase anywhere.** There is nothing to unlock — the node holds the
//!   identity. An agent session never sees a secret, which is what makes it safe
//!   to hand these verbs to model-authored code.
//! - **Rooms come and go here too.** `join` and `create` take the room passphrase on
//!   stdin, never argv, and `leave` takes none.
//!
//! The socket answers a deliberately narrow request set. There is no verb here that
//! creates an identity, unlocks, revokes, or edits the trust keyring — `vox trust` is
//! an operator surface and is not part of this module.

use std::io::Read as _;
use std::io::Write as _;
use std::path::Path;

use vox_core::hash::Digest32;
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::link::{b32_decode, b32_encode, B32_DIGEST_LEN};
use vox_core::node::paths::Paths;

use crate::app::AppError;
use crate::tunnel_cli::resolve_prefix;

/// Connect to the daemon as this node, which must be attached already (ADR-026 L-2: a one-shot
/// verb never attaches).
///
/// Each way it fails needs a different remedy, so each gets its own sentence (#191): no daemon
/// running, the node not attached (the daemon's refusal says how to attach it), a socket that is
/// not this user's.
pub(crate) async fn attach(paths: &Paths) -> Result<IpcClient, AppError> {
    let at = crate::client::one_shot(paths)?;
    let mut client = crate::client::open(&at).await?;
    // Every author this command prints is named as this node names it (V210-162).
    crate::ident::load_names(&mut client).await;
    Ok(client)
}

/// Ask the node for its rooms, as `(id, local name, open, over)`.
async fn rooms_of(
    client: &mut IpcClient,
) -> Result<Vec<(Digest32, String, bool, String)>, AppError> {
    match client.rooms().await {
        Ok(Frame::Rooms { rooms }) => Ok(rooms),
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(crate::client::unexpected(&other)),
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
    // A stamp can be later than this clock: another member's clock is ahead, or a post was
    // stamped after one it held (V210-168). Say so rather than "0s ago".
    let span = |n: u64| {
        if n < 60 {
            format!("{n}s")
        } else if n < 3600 {
            format!("{}m", n / 60)
        } else if n < 86_400 {
            format!("{}h{:02}m", n / 3600, (n % 3600) / 60)
        } else {
            format!("{}d", n / 86_400)
        }
    };
    let elapsed = if since_secs > now {
        format!("{} ahead of this clock", span(since_secs - now))
    } else {
        format!("{} ago", span(now - since_secs))
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

/// Resolve a room's name (ADR-028 R-1), or a prefix of its id, against what the node holds, and
/// insist it is open. A name is matched whole, and only when one room holds it.
///
/// A closed room is reported as closed rather than "unknown": the two are
/// different problems and an operator fixes them differently.
pub(crate) async fn room_of(client: &mut IpcClient, prefix: &str) -> Result<Digest32, AppError> {
    let rooms = rooms_of(client).await?;
    if rooms.is_empty() {
        return Err(AppError::Usage(
            "this node holds no rooms yet — join or create one first".into(),
        ));
    }
    let ids: Vec<Digest32> = rooms.iter().map(|(id, _, _, _)| *id).collect();
    let named: Vec<Digest32> = rooms
        .iter()
        .filter(|(_, name, _, _)| !name.is_empty() && name.eq_ignore_ascii_case(prefix.trim()))
        .map(|(id, _, _, _)| *id)
        .collect();
    let id = match named.as_slice() {
        [one] => *one,
        _ => resolve_prefix(prefix, &ids)?,
    };
    // A closed room's name is sealed in its manifest, so a node that has not opened it does
    // not know it: the name here is empty, and printing it said `room "" is not open` (#208).
    // Named by the id the operator typed a prefix of, and by its name only when there is one.
    if let Some((_, name, false, _)) = rooms.iter().find(|(r, _, _, _)| *r == id) {
        return Err(room_closed(&id, name));
    }
    Ok(id)
}

/// What every verb says of a room the node holds closed, with a daemon or without one
/// (`vox service list`'s one-shot form, V210-149).
pub(crate) fn room_closed(id: &Digest32, name: &str) -> AppError {
    let which = if name.is_empty() {
        format!("room {}", b32_encode(id))
    } else {
        format!("room {name:?} ({})", b32_encode(id))
    };
    AppError::Usage(format!(
        "{which} is closed on this node, so there is nothing to read or post. A daemon \
         reopens every room it held open, so this one was closed in `vox tui` or did not \
         reopen (its log says why). Open it in `vox tui`, or join it again: `vox room join` \
         with its address and passphrase opens a room this node holds closed"
    ))
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
    for (id, name, open, over) in rooms {
        println!(
            "{}  {}{}{}",
            short(&id),
            if name.is_empty() { "(unnamed)" } else { &name },
            if open { "" } else { "  [closed]" },
            if over.is_empty() {
                String::new()
            } else {
                format!("  [{over}]")
            }
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
pub(crate) async fn post(paths: &Paths, room: &str, text: Option<&str>) -> Result<(), AppError> {
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
        Ok(other) => Err(crate::client::unexpected(&other)),
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
    /// Addressees: the poster's names for members, or their fingerprints.
    pub to: Vec<String>,
    /// May interrupt the agents of the nodes addressed.
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

/// A room's members, as the node holds them.
async fn members_of(
    client: &mut IpcClient,
    channel_id: Digest32,
) -> Result<Vec<Digest32>, AppError> {
    match client.request(&Request::Roster { channel_id }).await {
        Ok(Frame::Members { members }) => Ok(members),
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `--to`, as the envelope carries it (V210-161): each word resolved by the poster, once, to a
/// member's whole fingerprint, so every reader resolves it to the same node. A word that names
/// no member is refused, saying why.
pub(crate) async fn addressees(
    client: &mut IpcClient,
    channel_id: Digest32,
    words: &[String],
) -> Result<Vec<String>, AppError> {
    if words.is_empty() {
        return Ok(Vec::new());
    }
    let members = members_of(client, channel_id).await?;
    let mut to: Vec<String> = Vec::new();
    for w in words {
        let fp = crate::ident::resolve_member(w, &members, crate::ident::names())
            .map_err(|e| AppError::Usage(format!("refusing --to: {e}")))?;
        let fp = b32_encode(&fp);
        if !to.contains(&fp) {
            to.push(fp);
        }
    }
    Ok(to)
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
        // An envelope every reader would refuse is refused here, before it is posted
        // (V210-123): a type or name not on one line would otherwise sit in the log unread.
        if let Err(e @ vox_agentcomms::envelope::ParseError::Malformed(_)) = Envelope::parse(&body)
        {
            return Err(AppError::Usage(format!("refusing to post it: {e}")));
        }
        if let Ok(env) = Envelope::parse(&body) {
            // **A raw envelope addresses members by fingerprint** (V210-161), as `--to` writes
            // them: a name in `to` would read as addressed to nobody on every node.
            if !env.to.is_empty() {
                let (mut client, cid, _) = open_room(paths, room).await?;
                let members = members_of(&mut client, cid).await?;
                if let Some(bad) = env
                    .to
                    .iter()
                    .find(|t| !crate::ident::recipient(t).is_some_and(|fp| members.contains(&fp)))
                {
                    return Err(AppError::Usage(format!(
                        "refusing to post it: `to` names {:?}, which is not a member's whole \
                         fingerprint as `vox room roster` prints it. Use --to, which takes your \
                         name for a member or its fingerprint",
                        vox_agentcomms::envelope::shown(bad, vox_agentcomms::envelope::SHOWN_NAME)
                    )));
                }
            }
            if claim::is_claim_protocol(&env) {
                return Err(AppError::Usage(format!(
                    "refusing a raw `{}`: claim-protocol operations need a session, an \
                     operation id and a version stamp. Use `vox room {}`.",
                    env.kind, env.kind
                )));
            }
            // **A raw envelope cannot start an urgent chain of its own from a woken session**
            // (V210-121): it is posted exactly as given, so it would not inherit the `re` a
            // structured post takes, and two agents answering each other that way woke each
            // other for ever.
            if env.urgent && env.re.is_none() {
                if let Some(session) = coord::session(opts.coord.session.as_deref()) {
                    let (mut client, cid, room_key) = open_room(paths, room).await?;
                    let me = client
                        .me()
                        .ok_or_else(|| AppError::Usage("the node did not say who it is".into()))?;
                    // The wakes and what followed the oldest of them (V210-120).
                    let rows =
                        coord::wake_context(&mut client, cid, paths, &session, &room_key).await?;
                    let open = crate::wake::open_wakes(paths, &session, &room_key, &rows, &me);
                    if !open.is_empty() {
                        return Err(AppError::Usage(format!(
                            "refusing a raw urgent message with no `re` from session {session}: \
                             it was woken by {} and has not answered. Reply with `--re <entry>`, \
                             or post with the structured flags (`--type`, `--to`, `--urgent`), \
                             which answer the message that woke it when only one is open.",
                            open.join(", ")
                        )));
                    }
                }
            }
        }
        return post(paths, room, Some(&body)).await;
    }

    let kind = opts.kind.clone().unwrap_or_else(|| "say".into());
    if !vox_agentcomms::envelope::is_valid_name(&kind, vox_agentcomms::envelope::MAX_NAME) {
        return Err(AppError::Usage(format!(
            "--type {} is refused: a type must be at most {} bytes on one line, with no control \
             characters, line separators or bidi controls, because other agents' rooms print it",
            vox_agentcomms::envelope::shown(&kind, vox_agentcomms::envelope::SHOWN_NAME),
            vox_agentcomms::envelope::MAX_NAME
        )));
    }
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
                 [a-z][a-z0-9-]{{0,15}} and the id 1–{} of [A-Za-z0-9._~/#:-]",
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

    // **A person addresses a message with no session**: a `say` — with `--to`, `--urgent`
    // or `--re` — is posted as the node, its `from` empty, when nothing names a session. Only
    // work coordination is owned per session: another type, a work item or an attempt needs one.
    let coordinates =
        kind != vox_agentcomms::envelope::SAY || work.is_some() || opts.attempt.is_some();
    let session = if coordinates {
        coord::require_session(opts.coord.session.as_deref())?
    } else {
        coord::session(opts.coord.session.as_deref()).unwrap_or_default()
    };
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
    let to = addressees(&mut client, cid, &opts.to).await?;
    let snap = if work.is_some() {
        coord::participate(paths, &mut client, cid, &room_key, &session).await?
    } else {
        coord::snapshot(&mut client, cid).await?
    };
    // **The attempt id, when the caller did not name one** (ADR-021 §2). It is seeded
    // from the log alone — the hash of this session's claim on the work item, or of its
    // own latest `failed` for that item since the claim — so an agent never mints one and
    // a tracker can correlate every post of one attempt. **Seeding starts nothing**: an
    // attempt becomes active only when the holder posts `working` (§3), and that entry is
    // its start evidence; a `failed` seeds the id of a retry that does not exist until the
    // next `working`. A retried `--op` keeps the id its first post carried — the claim may
    // have been renewed, re-taken or failed since, and a different id would make the retry
    // a conflict rather than the same message.
    if let (Some(w), None) = (&work, data.get("attempt")) {
        // A retry's earlier post, read by its operation id (V210-120): the snapshot holds the
        // coordination posts, not every post an operation id may be on.
        let earlier = coord::op_group(&mut client, cid, &op)
            .await?
            .into_iter()
            .find(|p| p.author == snap.me && vox_agentcomms::ops::op_of(&p.envelope) == Some(&op))
            .and_then(|p| p.envelope.data.get("attempt").cloned());
        let seeded = match snap.fold.resources.get(w) {
            Some(State::Held {
                owner, acquisition, ..
            }) if owner.author == snap.me && owner.session == session => {
                Some(seeded_attempt_id(&snap, w, &session, *acquisition))
            }
            _ => None,
        };
        if let Some(a) = earlier.or(seeded.map(|h| claim::b32(&h).into())) {
            data.insert("attempt".into(), a);
        }
    }
    let (re, hops_of_reply) = answers(
        &mut client,
        cid,
        paths,
        (!session.is_empty()).then_some(session.as_str()),
        &snap.me,
        opts.re.as_deref(),
        opts.urgent,
    )
    .await?;
    let draft = Draft {
        kind,
        to,
        urgent: opts.urgent,
        re: re.clone(),
        thread: opts.thread.clone(),
        // **A reply spends a hop** (ADR-020 §9): what it may still travel is its parent's
        // budget less one, so an urgent reply chain ends at zero instead of looping.
        hops: hops_of_reply,
        body: body.trim_end().to_owned(),
        data,
    };
    let is_result = draft.kind == vox_agentcomms::envelope::work::RESULT;
    let posting = coord::post_once(&mut client, cid, &draft, &session, &op, &snap).await?;
    // **An addressee that cannot be interrupted is named to the poster** (V210-169): the
    // message is posted, and waits in the room for that session's next turn. This node's
    // sessions only: another node decides for its own.
    let me = client.me().map(|m| b32_encode(&m)).unwrap_or_default();
    if opts.urgent {
        if let Some(line) = crate::wake::uninterruptible(paths, &me, &draft.to) {
            eprintln!("vox: {line}");
        }
    }
    // **What to expect of each other node addressed** (V030-17), from the room as it stands
    // after the post. This node's own sessions are covered by the line above, from their
    // registrations, which say more than the room does.
    let others: Vec<Digest32> = draft
        .to
        .iter()
        .filter(|fp| **fp != me)
        .filter_map(|fp| crate::ident::recipient(fp))
        .collect();
    let reach = if others.is_empty() {
        Vec::new()
    } else {
        let (outbound, inbound) = match client.request(&Request::Consents { channel_id: cid }).await
        {
            Ok(Frame::Consents { outbound, inbound }) => (outbound, inbound),
            Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
            Ok(other) => return Err(crate::client::unexpected(&other)),
            Err(e) => return Err(AppError::Usage(e.to_string())),
        };
        // When each last posted as an agent: the room's structured posts, by author.
        use vox_agentcomms::envelope::{work, SAY};
        let kinds = [
            SAY,
            work::ASSIGN,
            work::ACCEPT,
            work::DECLINE,
            work::WORKING,
            work::BLOCKED,
            work::STATUS,
            work::RESULT,
            work::FAILED,
            work::ASK,
            work::ANSWER,
        ];
        let rows = coord::structured(&mut client, cid, &kinds, &[]).await?;
        others
            .iter()
            .map(|fp| {
                let last = rows
                    .iter()
                    .filter(|r| r.author == *fp)
                    .map(|r| r.created_millis)
                    .max();
                reach_of(&posting.after, fp, last, draft.urgent, &outbound, &inbound)
            })
            .collect()
    };
    // **A `result` says what it has not read** (ADR-021 M21.10). A redirect addressed
    // to this session can land after its last drain and before it reports; the result
    // still posts, and the caller is shown every such message so it can follow up.
    let unread = if is_result {
        // What follows this session's drain cursor, read from there (V210-120); the whole room
        // only if the node no longer holds that cursor.
        let cursor = crate::agent_hook::load_cursor(paths, &room_key, &session);
        let after = match coord::read_all(&mut client, cid, cursor).await {
            Ok(rows) => rows,
            Err(_) => coord::read_all(&mut client, cid, None).await?,
        };
        unread_addressed(&session, &posting, &after)
    } else {
        Vec::new()
    };
    if opts.coord.json {
        let mut out = serde_json::json!({
            "schema": "vox.room.post/1",
            "room": room_key,
            "entry_hash": claim::b32(&posting.entry_hash),
            "op": posting.op,
            "status": posting.status,
            "session": (!session.is_empty()).then_some(&session),
        });
        if !reach.is_empty() {
            out["reach"] = reach.iter().map(Reach::json).collect();
        }
        if is_result {
            out["unread_addressed"] = serde_json::Value::Array(
                unread
                    .iter()
                    .map(|(h, from, kind, body)| {
                        serde_json::json!({"entry_hash": h, "from": from, "type": kind, "body": body})
                    })
                    .collect(),
            );
        }
        println!("{out}");
    }
    for r in &reach {
        eprintln!("vox: to {}: {}", r.name, r.says);
    }
    if !unread.is_empty() {
        eprintln!(
            "vox: your result is posted, but {} message(s) addressed to you are unread — \
             read them before moving on:",
            unread.len()
        );
        for (h, from, kind, body) in &unread {
            eprintln!("  {} {from} [{kind}] {body}", &h[..12]);
        }
    }
    Ok(())
}

/// What a sender can expect of one other node it addressed (V030-17): whether any of its
/// sessions has announced itself in this room, whether an urgent message can interrupt one, when
/// it last posted as an agent, and trust in each direction. Only what this node can see: it never
/// says a reply is overdue, because it cannot see another node's reads.
struct Reach {
    /// The node, as this node names it.
    name: String,
    /// The `data.wake` of each of its sessions' `hello`s still in force (no later `bye`): `""`
    /// for a hello that did not say. Empty when none announced itself.
    wakes: Vec<String>,
    /// When it last posted as an agent (a structured post), ms since the epoch.
    last_posted: Option<u64>,
    /// Whether this identity consents to it reading, and it to this identity.
    you_trust: bool,
    it_trusts: bool,
    /// The line shown.
    says: String,
}

impl Reach {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "announced": !self.wakes.is_empty(),
            "wake": self.wakes,
            "last_posted_millis": self.last_posted,
            "you_trust": self.you_trust,
            "it_trusts": self.it_trusts,
            "says": self.says,
        })
    }
}

/// How long ago `then` was, at `now` (both ms), coarsely: `40s`, `12m`, `3h`, `2d`.
fn ago(now: u64, then: u64) -> String {
    let s = now.saturating_sub(then) / 1000;
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        3600..=86_399 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

/// [`Reach`] for the node `fp`, from `snap`, the room after the post, when it `last_posted`, and
/// this identity's
/// consents in the room in each direction.
fn reach_of(
    snap: &coord::Snapshot,
    fp: &Digest32,
    last_posted: Option<u64>,
    urgent: bool,
    outbound: &[Digest32],
    inbound: &[Digest32],
) -> Reach {
    use vox_agentcomms::envelope::{BYE, HELLO};
    let theirs = || snap.posted.iter().filter(|p| p.author == *fp);
    // A session's hello is in force until a later `bye` from the same session.
    let wakes: Vec<String> = theirs()
        .filter(|h| h.envelope.kind == HELLO)
        .filter(|h| {
            !theirs().any(|b| {
                b.envelope.kind == BYE
                    && b.envelope.from == h.envelope.from
                    && b.created_millis >= h.created_millis
            })
        })
        .map(|h| {
            h.envelope
                .data
                .get(crate::wake::WAKE_KEY)
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned()
        })
        .collect();
    let mut parts = Vec::new();
    if wakes.is_empty() {
        parts.push("none of its sessions has announced itself in this room".to_owned());
    } else {
        let any = |w: &str| wakes.iter().any(|x| x == w);
        parts.push(
            if !urgent {
                "not urgent, so it is read at its sessions' next turn"
            } else if any("interrupt") {
                "urgent may interrupt a session there"
            } else if any("") {
                "a hello there does not say whether it can be interrupted; it is read at the next \
                 turn"
            } else {
                "urgent will not interrupt it; it is read at its sessions' next turn"
            }
            .to_owned(),
        );
    }
    let (you_trust, it_trusts) = (outbound.contains(fp), inbound.contains(fp));
    parts.push(
        if you_trust {
            "you trust it"
        } else {
            "you have not trusted it, so it cannot read this"
        }
        .to_owned(),
    );
    parts.push(
        if it_trusts {
            "it trusts you"
        } else {
            "it has not trusted you"
        }
        .to_owned(),
    );
    if let Some(t) = last_posted {
        parts.push(format!("last posted {} ago", ago(snap.now_millis, t)));
    }
    Reach {
        name: crate::ident::name_of(fp),
        wakes,
        last_posted,
        you_trust,
        it_trusts,
        says: parts.join("; "),
    }
}

/// Messages addressed to this node that this session's drain has not delivered yet: past its
/// drain cursor, not its own, naming this node in `to` (V210-161). The one just posted is
/// excluded.
fn unread_addressed(
    session: &str,
    posting: &coord::Posting,
    after_cursor: &[vox_core::node::api::MessageRow],
) -> Vec<(String, String, String, String)> {
    let snap = &posting.after;
    let me = b32_encode(&snap.me);
    after_cursor
        .iter()
        .filter(|r| r.entry_hash != posting.entry_hash)
        .filter_map(|r| {
            let env = Envelope::parse(&r.text).ok()?;
            let own = r.author == snap.me && env.from == session;
            (!own && env.is_addressed_to(&me)).then(|| {
                // Every field is the author's, and this lands on the reporting agent's stderr: each
                // is shown on one line and cut (V210-123). The body's first line ends at any
                // character a reader breaks a line at, not only `\n`.
                use vox_agentcomms::envelope::{breaks_lines, shown, SHOWN_NAME};
                let first = env.body.trim_start();
                let first = first.split(breaks_lines).next().unwrap_or("");
                (
                    claim::b32(&r.entry_hash),
                    crate::ident::name_of(&r.author),
                    shown(&env.kind, SHOWN_NAME),
                    shown(first, 160),
                )
            })
        })
        .collect()
}

/// The entry that seeds the holder's default attempt id on `work`: its claim's
/// acquisition, or its own latest `failed` for `work` after it, in canonical order
/// `(created_millis, entry_hash)`. A `failed` whose operation is void (a conflict, §6)
/// never happened, so it seeds nothing; a retried one is its first entry, not the retry.
fn seeded_attempt_id(
    snap: &coord::Snapshot,
    work: &str,
    session: &str,
    acquisition: [u8; 32],
) -> [u8; 32] {
    let Some(start) = snap.posted.iter().find(|p| p.entry_hash == acquisition) else {
        return acquisition;
    };
    let ops = snap.ops();
    snap.posted
        .iter()
        .filter(|p| {
            p.author == snap.me
                && p.envelope.from == session
                && p.envelope.kind == vox_agentcomms::envelope::work::FAILED
                && coord::work_of(&p.envelope) == Some(work)
                && (p.created_millis, p.entry_hash) > (start.created_millis, start.entry_hash)
                && !matches!(
                    ops.verdict(p.author, &p.envelope, p.entry_hash),
                    Some(
                        vox_agentcomms::ops::Verdict::Conflict { .. }
                            | vox_agentcomms::ops::Verdict::Duplicate { .. }
                    )
                )
        })
        .max_by_key(|p| (p.created_millis, p.entry_hash))
        .map_or(acquisition, |p| p.entry_hash)
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
    row_value(room_key, r, ops, status_override).to_string()
}

/// [`row_json`]'s object.
fn row_value(
    room_key: &str,
    r: &vox_core::node::api::MessageRow,
    ops: &vox_agentcomms::ops::OpIndex,
    status_override: Option<&str>,
) -> serde_json::Value {
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
        "owed": r.owed,
        "envelope": envelope,
        // `envelope.to` as this reader names each addressee (PRD-001 R15): "you" for this node,
        // its keyring name, or the fingerprint where it has none. Never a name another node gave.
        "to_names": parsed.as_ref().ok().map(|e| {
            e.to.iter()
                .map(|t| crate::ident::recipients(std::slice::from_ref(t), crate::ident::me(), crate::ident::names()))
                .collect::<Vec<_>>()
        }).unwrap_or_default(),
        "parse_error": parse_error,
        "op": op,
    })
}

/// Who has read this node's own recent messages in `room`, by entry, as the node's snapshot says
/// (ADR-028 R-6): from the read records it can open, so a member whose records it cannot open is
/// in none. Empty when the node does not say.
async fn read_by_in(
    client: &mut IpcClient,
    room: &Digest32,
) -> std::collections::BTreeMap<Digest32, Vec<Digest32>> {
    let body = vox_core::node::snapshot::request_body();
    let Ok(reply) = client.exchange(&body).await else {
        return std::collections::BTreeMap::new();
    };
    let Ok(Some(snap)) = vox_core::node::snapshot::NodeSnapshot::from_bytes(&reply) else {
        return std::collections::BTreeMap::new();
    };
    snap.open
        .into_iter()
        .find(|o| o.channel_id == *room)
        .map(|o| o.read_by.into_iter().collect())
        .unwrap_or_default()
}

/// Where in the timeline `cursor` sits, or a refusal: an unknown cursor is never
/// silently treated as "from the beginning", which would re-deliver or skip without
/// anyone knowing.
fn after_cursor(
    rows: &[vox_core::node::api::MessageRow],
    cursor: Option<Digest32>,
) -> Result<Vec<&vox_core::node::api::MessageRow>, AppError> {
    // **Arrival, not position** (ADR-023 decision 1): the room is shown in its one order, where a
    // late arrival lands *above* rows already shown, so "everything below the cursor" would skip it
    // for good. What follows a cursor is what this node rendered after it, in the order it
    // rendered it, so the last row is always the right next cursor — the same rule the node
    // applies to `Read { since }`.
    match cursor {
        None => Ok(rows.iter().collect()),
        Some(c) => {
            let row = rows.iter().find(|r| r.entry_hash == c).ok_or_else(|| {
                AppError::Usage(format!("cursor {} is not in this room's timeline", id(&c)))
            })?;
            // A message not received yet has no arrival to read on from (V030-10).
            if row.owed {
                return Err(AppError::Usage(format!(
                    "cursor {} is a message not received yet; read on from one that has arrived",
                    id(&c)
                )));
            }
            let mark = row.arrival;
            let mut newer: Vec<&vox_core::node::api::MessageRow> =
                rows.iter().filter(|r| r.arrival > mark).collect();
            newer.sort_by_key(|r| r.arrival);
            Ok(newer)
        }
    }
}

/// One row as `vox room read` and `tail` print it: `<entry-hash> <author> <text>`, the author
/// by this node's name for it, or its fingerprint when it has none (V210-162).
///
/// **No message can forge a row** (PRD-001 R19). A row starts at the beginning of a line,
/// so a message carrying a newline followed by `<hash> <author> …` would otherwise print a
/// second row attributed to someone else — and agents read this output. Every continuation
/// line is therefore indented with `  | `, which no row begins with, and every other
/// control character (a carriage return, an escape sequence) and the Unicode line and
/// paragraph separators are shown escaped rather than passed on. `--json` needs none of this: each row is one JSON-escaped line.
fn plain_row(r: &vox_core::node::api::MessageRow) -> String {
    // A message whose envelope is held and whose body is still asked for (V030-10).
    if r.owed {
        return format!(
            "{} {} {}",
            id(&r.entry_hash),
            // Named as every other row names its author: by the reader's name (V210-162).
            crate::ident::name_of(&r.author),
            vox_core::node::api::NOT_RECEIVED_YET
        );
    }
    let mut text = String::with_capacity(r.text.len());
    // Characters a reader cannot see, and every other that could break or reorder the row (a
    // carriage return, an escape sequence, U+2028, a bidi override), are shown as escapes,
    // `⟨U+XXXX⟩`, the style the drain and the TUI use (#331). A newline is indented, a tab kept.
    // A structured post is read as the drain and the TUI show it, not as its JSON (#406):
    // `--json` keeps the envelope for programs.
    let said = crate::agent_hook::words(&r.text);
    for c in vox_agentcomms::envelope::reveal_keeping(&said, |c| c == '\n' || c == '\t').chars() {
        match c {
            '\n' => text.push_str("\n  | "),
            c => text.push(c),
        }
    }
    // **Who it is addressed to, as this reader names them** (PRD-001 R15): the wire carries
    // fingerprints, so the raw text alone shows a reader only those. Said on a line of its own,
    // after the text, so the `<entry> <author> <text>` columns are unchanged; a line of the text
    // cannot begin like it, since every further line of the text is behind `  | `.
    let to = crate::agent_hook::addressed(&r.text, crate::ident::me(), crate::ident::names());
    let to = if to.is_empty() {
        String::new()
    } else {
        format!("\n  ({to})")
    };
    format!(
        "{} {} {}{to}",
        id(&r.entry_hash),
        crate::ident::name_of(&r.author),
        text
    )
}

/// What a post answers and the hop budget it starts with, by the one rule `vox room post` and
/// `vox share` follow (V210-121, ADR-020 §9): `re` if given, else the one unanswered message that
/// woke `session`; and that parent's budget less one.
///
/// # Errors
/// An urgent post from a session woken by several unanswered messages names none of them, or a
/// parent cannot be read.
pub(crate) async fn answers(
    client: &mut IpcClient,
    cid: Digest32,
    paths: &Paths,
    session: Option<&str>,
    me: &Digest32,
    re: Option<&str>,
    urgent: bool,
) -> Result<(Option<String>, Option<u32>), AppError> {
    // **A woken session's post answers what woke it** (V210-121). With no `--re` it started a
    // chain of its own with a fresh hop budget, and two agents answering each other urgently
    // that way woke each other for ever. When exactly one wake is unanswered, that is the reply;
    // with several, the agent must say which.
    let re = match (re, session) {
        (Some(re), _) => Some(re.to_owned()),
        (None, None) => None,
        (None, Some(session)) => {
            // The wakes and what followed the oldest of them, read from there (V210-120).
            let rows = coord::wake_context(client, cid, paths, session, &id(&cid)).await?;
            let open = crate::wake::open_wakes(paths, session, &id(&cid), &rows, me);
            match &open[..] {
                [] => None,
                [only] => {
                    eprintln!(
                        "vox: replying to {} (the message that woke this session); pass --re to \
                         answer another",
                        &only[..12.min(only.len())]
                    );
                    Some(only.clone())
                }
                // **Several unanswered, and an urgent post must say which it answers** (V210-121).
                // Sent with no `re` it started a chain of its own at a fresh budget, and a session
                // that left two wakes unanswered stayed that way: every later wake added to the
                // set rather than being inherited, and two such sessions woke each other for ever.
                several if urgent => {
                    return Err(AppError::Usage(format!(
                        "refusing an urgent message with no --re from session {session}: it was \
                         woken by {} messages it has not answered ({}). Pass --re <entry> to say \
                         which one this answers.",
                        several.len(),
                        several.join(", ")
                    )));
                }
                _ => None,
            }
        }
    };
    // **A reply spends a hop** (ADR-020 §9): what it may still travel is its parent's budget
    // less one. Its parents are fetched by entry hash (V210-120), not by reading the room.
    let hops_of_reply = match &re {
        Some(re) => Some(crate::wake::reply_hops(
            re,
            &coord::reply_chain(client, cid, re).await?,
        )),
        None => None,
    };
    Ok((re, hops_of_reply))
}

/// `vox room read` — the room's messages, optionally only what follows a cursor.
///
/// Each line is `<entry-hash> <author> <text>`; with `--json`, one
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
    only_late: bool,
) -> Result<(), AppError> {
    let (mut client, channel_id, room_key) = open_room(paths, room).await?;
    let since = match since {
        None => None,
        Some(s) => Some(parse_cursor(s)?),
    };
    if !json {
        // No further than `--limit` (V210-120): a limit was applied only after every row past
        // the cursor had been read. `--late` filters, so it reads on and keeps `--limit` of those.
        let take = usize::try_from(limit).unwrap_or(usize::MAX);
        let read = if only_late { 0 } else { take };
        let Some(rows) = coord::read_upto(&mut client, channel_id, since, read).await? else {
            return Err(AppError::Usage(format!(
                "cursor {} is not in this room's timeline",
                since.map(|c| id(&c)).unwrap_or_default()
            )));
        };
        let held_back = equivocations_in(paths, &channel_id).await;
        let mut out = std::io::stdout().lock();
        // **A member held back for equivocating is said first** (V210-63), named as the rows
        // below name it. `vox status --json` carries the same, in full, for agents.
        for (author, seq) in &held_back {
            let _ = writeln!(
                out,
                "! {}",
                crate::ident::equivocation_notice(&crate::ident::name_of(author), *seq)
            );
        }
        let take = if take == 0 { usize::MAX } else { take };
        for r in rows.iter().filter(|r| r.late || !only_late).take(take) {
            let _ = writeln!(out, "{}", plain_row(r));
        }
        return Ok(());
    }
    // Only the rows asked for, and only the operations they carry (V210-120). An operation's
    // verdict needs its whole group, and an entry after the cursor may repeat, or conflict with,
    // one before it: so each shown row's group is read by its id, from the node's index, rather
    // than the whole room on every call. `--late` filters, so it reads on and keeps `--limit` of
    // those.
    let take = usize::try_from(limit).unwrap_or(usize::MAX);
    let read = if only_late { 0 } else { take };
    let Some(shown) = coord::read_upto(&mut client, channel_id, since, read).await? else {
        return Err(AppError::Usage(format!(
            "cursor {} is not in this room's timeline",
            since.map(|c| id(&c)).unwrap_or_default()
        )));
    };
    let take = if take == 0 { usize::MAX } else { take };
    let shown: Vec<_> = shown
        .into_iter()
        .filter(|r| r.late || !only_late)
        .take(take)
        .collect();
    let mut ids: Vec<String> = shown
        .iter()
        .filter_map(|r| Envelope::parse(&r.text).ok())
        .filter_map(|e| vox_agentcomms::ops::op_of(&e).map(str::to_owned))
        .collect();
    ids.sort();
    ids.dedup();
    let group = coord::structured(&mut client, channel_id, &[], &ids).await?;
    let ops = coord::index_of(&coord::posted_of(&group));
    let read_by = read_by_in(&mut client, &channel_id).await;
    let mut out = std::io::stdout().lock();
    for r in &shown {
        let mut row = row_value(&room_key, r, &ops, None);
        // Under a message this node sent, who has read it, by this node's names (ADR-028 R-6).
        if let Some(who) = read_by.get(&r.entry_hash) {
            let mut names: Vec<String> = who.iter().map(crate::ident::name_of).collect();
            names.sort();
            row["read_by"] = names.into();
        }
        let _ = writeln!(out, "{row}");
    }
    Ok(())
}

/// The services of the tunnels open to or from `member`, each with its count (`22 ×2`), from
/// `vox status`. Empty when the node does not say.
async fn tunnels_to(paths: &Paths, member: &Digest32) -> Vec<String> {
    let Ok(at) = crate::client::one_shot(paths) else {
        return Vec::new();
    };
    let Ok(json) = vox_core::node::status::request(&at).await else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) else {
        return Vec::new();
    };
    let member = vox_core::node::link::b32_encode(member);
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for t in v
        .get("tunnels")
        .and_then(|t| t.as_array())
        .into_iter()
        .flatten()
        .filter(|t| t.get("peer").and_then(|p| p.as_str()) == Some(member.as_str()))
    {
        let service = t.get("service").and_then(|s| s.as_str()).unwrap_or("?");
        *counts.entry(service.to_owned()).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(s, n)| if n == 1 { s } else { format!("{s} ×{n}") })
        .collect()
}

/// The members the node holds back for equivocating in `room` (V210-63), from `vox status`.
/// Empty when the node does not say: the rows are still worth printing.
async fn equivocations_in(paths: &Paths, room: &Digest32) -> Vec<(Digest32, u64)> {
    let Ok(at) = crate::client::one_shot(paths) else {
        return Vec::new();
    };
    let Ok(json) = vox_core::node::status::request(&at).await else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) else {
        return Vec::new();
    };
    let room = vox_core::node::link::b32_encode(room);
    v["equivocations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["room"].as_str() == Some(room.as_str()))
        .filter_map(|e| {
            let author =
                vox_core::node::link::b32_decode(e["author"].as_str()?, "equivocating author")
                    .ok()?;
            Some((author, e["position"].as_u64()?))
        })
        .collect()
}

/// `vox room read --hashes` — every entry the node holds for the room, one per line as
/// `<entry-hash> <clock-ms>`, in the room's one order (ADR-023 decision 1). The clock is the
/// key that placed the entry: its claimed time, capped and lifted by what it saw.
///
/// The timeline shows only rows this node can decrypt, so two members' timelines can
/// differ for reasons that have nothing to do with order: one holds a key the other
/// does not yet. This is the sequence underneath both, and the one that must match.
pub async fn order(paths: &Paths, room: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client.request(&Request::Order { channel_id }).await {
        Ok(Frame::Order { entries }) => {
            let mut out = std::io::stdout().lock();
            for (h, clock) in entries {
                let _ = writeln!(out, "{} {clock}", id(&h));
            }
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
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
        Ok(other) => Err(crate::client::unexpected(&other)),
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
    // **Test-only: a pause between the subscription and the read** (V030-31, #368), read from
    // `VOX_TEST_TAIL_HOLD_MS` in a build with the `test-knobs` feature; no shipped build reads it
    // (V210-105). Rows posted in it land between the two steps every time, which is the moment
    // the order exists for.
    #[cfg(feature = "test-knobs")]
    if let Some(ms) = std::env::var("VOX_TEST_TAIL_HOLD_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        eprintln!("vox: test-knobs: tail holding {ms} ms between its subscribe and its read");
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    let all = coord::read_all(&mut lookup, channel_id, None).await?;
    // With no cursor, a tail starts at the live edge, as it always has; everything
    // already in the room is context for the operation index, not output.
    let wanted: std::collections::HashSet<Digest32> = match cursor {
        None => std::collections::HashSet::new(),
        Some(_) => after_cursor(&all, cursor)?
            .into_iter()
            .map(|r| r.entry_hash)
            .collect(),
    };

    let mut ops = vox_agentcomms::ops::OpIndex::new();
    let mut seen: std::collections::HashSet<Digest32> = std::collections::HashSet::new();
    let mut by_hash: std::collections::HashMap<Digest32, vox_core::node::api::MessageRow> =
        std::collections::HashMap::new();
    let mut last: Option<Digest32> = None;
    // How far this stream has READ the node's timeline — the last row a read returned, not the
    // last one emitted, since an own post arrives as `NewEntry` ahead of rows synced before it.
    let mut read_to: Option<Digest32> = all.last().map(|r| r.entry_hash);
    let mut out = std::io::stdout().lock();

    // Index everything, emit only what arrived after the cursor, in the order it arrived.
    let mut backlog: Vec<&vox_core::node::api::MessageRow> = Vec::new();
    for r in &all {
        // A message not received yet has not arrived: it is emitted when its body does
        // (V030-10), so it is not seen yet.
        if r.owed {
            continue;
        }
        seen.insert(r.entry_hash);
        by_hash.insert(r.entry_hash, r.clone());
        if let Ok(e) = Envelope::parse(&r.text) {
            ops.insert(r.entry_hash, r.author, r.created_millis, &e);
        }
        if wanted.contains(&r.entry_hash) {
            backlog.push(r);
        }
    }
    backlog.sort_by_key(|r| r.arrival);
    for r in backlog {
        emit_row(&mut out, &room_key, r, &ops, json, None);
        last = Some(r.entry_hash);
    }

    let mut deliver = |r: vox_core::node::api::MessageRow,
                       out: &mut std::io::StdoutLock<'_>,
                       ops: &mut vox_agentcomms::ops::OpIndex,
                       last: &mut Option<Digest32>| {
        if r.owed || !seen.insert(r.entry_hash) {
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
    // `Lagged`, the room is read from where this stream last read it, and whatever it has
    // not emitted is emitted.
    //
    // **From where it last read, never the whole room** (V210-113): a whole re-read made
    // every arriving message cost the room's history (one run: 122 re-reads of ~7.4 MB).
    // It is complete because a node's timeline only grows at its end: an entry rendered
    // late (its key arrived after it did) is appended when it is rendered, so it sits
    // after every row any earlier read returned — though not necessarily after the last
    // row *emitted*, which may be an own post that came as `NewEntry`; hence `read_to`.
    // A reopened room rebuilds its timeline in the same order (its cache rows'); should
    // the cursor be gone from it anyway, the room is read whole, once.
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
            // **The node stopping is a failure, not the end of the room** (V210-83). It exited 0
            // here, so a supervisor restarting a tail on failure never did, and a script read a
            // stream that had silently stopped as one that had finished.
            Ok(None) => {
                return Err(AppError::Usage(match last {
                    Some(h) => format!(
                        "the node stopped, so this tail stopped with it\n       start the node \
                         again, then resume with `vox room tail {room} --since {}`",
                        b32_encode(&h)
                    ),
                    None => format!(
                        "the node stopped, so this tail stopped with it\n       start the node \
                         again, then run `vox room tail {room}`"
                    ),
                }))
            }
            Err(e) => return Err(AppError::Usage(e.to_string())),
        };
        if reread {
            let rows = match lookup
                .read_rows(channel_id, read_to)
                .await
                .map_err(|e| AppError::Usage(e.to_string()))?
            {
                Frame::Rows { rows } => rows,
                Frame::Error { .. } if read_to.is_some() => {
                    coord::read_all(&mut lookup, channel_id, None).await?
                }
                other => return Err(crate::client::unexpected(&other)),
            };
            if let Some(r) = rows.last() {
                read_to = Some(r.entry_hash);
            }
            for r in rows {
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
// Converge, not agree at once: so a claim says "you hold it" only after every other
// member has it and folds it the same (V210-168; exit 5 when one cannot be reached).
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
    /// The room's id.
    cid: Digest32,
    /// The resource's state just before the post, as this node folded it.
    before: Option<State>,
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
    // Every node folds these names and prints them into its agents' contexts, so a name
    // that would not stay on one line is refused here, before anything is posted, as the
    // fold refuses it there (V210-123).
    use vox_agentcomms::envelope::{is_valid_name, shown, MAX_NAME, MAX_RESOURCE, SHOWN_NAME};
    for (key, max) in [("resource", MAX_RESOURCE), ("to_session", MAX_NAME)] {
        if let Some(v) = data.get(key).and_then(serde_json::Value::as_str) {
            if !is_valid_name(v, max) {
                return Err(AppError::Usage(format!(
                    "the {key} {} is refused: it must be at most {max} bytes on one line, with \
                     no control characters or line separators, because other agents' rooms \
                     print it",
                    shown(v, SHOWN_NAME)
                )));
            }
        }
    }
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
    let snap = coord::participate(paths, &mut client, cid, &room_key, &session).await?;
    let before = data
        .get("resource")
        .and_then(|v| v.as_str())
        .and_then(|r| snap.fold.resources.get(r))
        .cloned();
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
    // **A renewal is recorded when it is made** (V210-79), so a holding that lapses before this
    // session's next drain is still reported lost there. By what the operation did, not by
    // what the fold says now: a short ttl can already have run out by the read-back. A claim is
    // recorded by `claim_resource`, once the room's members have answered (V210-168).
    if kind == claim::RENEW && outcome == Some(Outcome::Applied) {
        if let Some(resource) = draft.data.get("resource").and_then(|v| v.as_str()) {
            crate::agent_hook::note_held(paths, &room_key, &session, resource);
        }
    }
    Ok(Done {
        posting,
        outcome,
        session,
        room: room_key,
        cid,
        before,
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

/// What a claim-protocol post did, as a sentence: never the outcome's debug form (R36).
fn outcome_words(o: Option<&Outcome>) -> String {
    match o {
        None => "this node has not folded the post yet, so what it did is not known".into(),
        Some(Outcome::Applied) => "it was applied".into(),
        Some(Outcome::Lost) => {
            "another session holds the resource, or it is reserved for someone else".into()
        }
        Some(Outcome::NoEffect(why)) => (*why).to_owned(),
        Some(Outcome::Invalid(why)) => format!("the post was not valid: {why}"),
        Some(Outcome::OtherVersion(s)) => format!(
            "the post is stamped {}, a claim-protocol version this vox does not fold",
            s.token()
        ),
        Some(Outcome::Duplicate { of }) => format!(
            "it repeats post {}, which was already applied",
            claim::b32(of)
        ),
        Some(Outcome::Conflict { group }) => format!(
            "{} posts share its operation id and disagree, so none of them has any effect",
            group.len()
        ),
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
    report_as(done, kind, resource, opts, ok, said, 1, None)
}

/// [`report`] with the exit status a refusal ends with, and anything a verb adds to its JSON.
#[allow(clippy::too_many_arguments)]
fn report_as(
    done: &Done,
    kind: &str,
    resource: &str,
    opts: &CoordOpts,
    ok: bool,
    said: &str,
    code: u8,
    extra: Option<(&str, serde_json::Value)>,
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
        let mut out = serde_json::json!({
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
        });
        if let (Some((key, value)), Some(map)) = (extra, out.as_object_mut()) {
            map.insert(key.to_owned(), value);
        }
        println!("{out}");
    } else if ok {
        println!("{said}");
    }
    if ok {
        Ok(())
    } else if opts.json || code != 1 {
        Err(AppError::Refused {
            code,
            message: said.to_owned(),
        })
    } else {
        Err(AppError::Usage(said.to_owned()))
    }
}

/// `<author>/<session>`, the session on one line and cut (V210-123): it is the author's
/// text, and this lands in other agents' contexts.
fn who(o: &Owner) -> String {
    format!(
        "{}/{}",
        crate::ident::name_of(&o.author),
        session_name(&o.session)
    )
}

/// An author-chosen session as this module prints it: one line, about 64 bytes (V210-123).
fn session_name(s: &str) -> String {
    vox_agentcomms::envelope::shown(s, vox_agentcomms::envelope::SHOWN_NAME)
}

/// An author-chosen resource as this module prints it: one line, cut (V210-123).
fn name(s: &str) -> String {
    vox_agentcomms::envelope::shown(s, vox_agentcomms::envelope::MAX_RESOURCE)
}

fn resource_of(resource: Option<&str>, work: Option<&str>) -> Result<String, AppError> {
    match (resource, work) {
        (Some(r), Some(w)) if r != w => Err(AppError::Usage(format!(
            "the resource {r:?} and --work {w:?} differ; a claim on a work item uses the \
             reference as its resource"
        ))),
        (_, Some(w)) if !vox_agentcomms::envelope::is_valid_work(w) => {
            Err(AppError::Usage(format!(
                "--work {w:?} is not a work reference: use <scheme>:<id>, the scheme \
                 [a-z][a-z0-9-]{{0,15}} and the id 1–{} of [A-Za-z0-9._~/#:-]",
                vox_agentcomms::envelope::MAX_WORK_ID
            )))
        }
        (Some(r), _) | (None, Some(r)) if !r.trim().is_empty() => Ok(r.to_owned()),
        _ => Err(AppError::Usage("name a resource, or pass --work".into())),
    }
}

/// `vox room claim` — take a resource, or complete a handoff pending for this session.
///
/// It says "you hold it" only once every other member of the room agrees (V210-168): see
/// `agreement`.
///
/// # Errors
/// Exit 1 if somebody else holds it, 3 on a version refusal, 4 on an op conflict, 5 if not every
/// member could agree.
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
    let mut done = run_op(
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
    // **Say whether it was won, and only once the room agrees** (V210-168). A claim is a post,
    // and this node folds it as won until a claim that crossed it arrives from another member:
    // two claims made at once were both told "you hold it". So a claim this node folds as won is
    // put to every other member first, and "you hold it" waits for every one of them to fold the
    // same. One that crossed another is put to them too, so the loser is told whose claim the
    // room orders first, which a third member's claim this node has not seen yet may be. The
    // current state is the answer, not this post's own outcome: on a retry the resource may have
    // moved on since the first attempt.
    //
    // Crossed: the holder's claim was not in this node's log when this one was made.
    let before = done.before.clone();
    let crossed = move |acquisition: &[u8; 32]| match &before {
        Some(State::Held { acquisition: a, .. }) => a != acquisition,
        _ => true,
    };
    let mut unagreed: Vec<(Digest32, String)> = Vec::new();
    let ask_the_room = match done.posting.after.fold.resources.get(&resource) {
        Some(State::Held { owner, .. }) if *owner == me => true,
        Some(State::Held { acquisition, .. }) => crossed(acquisition),
        Some(State::Pending { .. }) => false,
        None => true,
    };
    if ask_the_room {
        let (fold, why) = agreement(paths, &done, &me, &resource).await?;
        done.posting.after.fold = fold;
        unagreed = why;
    }
    let (ok, said, code) = match done.posting.after.fold.resources.get(&resource) {
        Some(State::Held { owner, .. }) if *owner == me && unagreed.is_empty() => {
            (true, format!("you hold {resource}"), 1)
        }
        Some(State::Held { owner, .. }) if *owner == me => (
            false,
            format!(
                "{resource} is not agreed yet: {}. Your claim is posted, but it is not sure to be \
                 yours{}.{} Run `vox room board {room}` later to see who holds it, claim it \
                 again to ask again, or release it",
                unagreed_text(&me.author, &unagreed),
                // A member that has not agreed can still post a claim ordered first. A post the
                // claim is stamped before is already made: the note below says what that means.
                if unagreed.iter().any(|(_, w)| !w.starts_with(STAMPED_AHEAD)) {
                    ": a claim by such a member can still be ordered before it, even one made \
                     after it"
                } else {
                    ""
                },
                clocks_note(&unagreed),
            ),
            coord::EXIT_UNAGREED,
        ),
        Some(State::Held {
            owner, acquisition, ..
        }) if crossed(acquisition) => (
            false,
            format!(
                "{resource} went to {}: your claims crossed and the room orders theirs first — \
                 you did not get it{}",
                who(owner),
                if clocks_note(&unagreed).is_empty() {
                    String::new()
                } else {
                    format!(
                        " ({}.{})",
                        unagreed_text(&me.author, &unagreed),
                        clocks_note(&unagreed)
                    )
                }
            ),
            1,
        ),
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
            1,
        ),
        Some(State::Pending {
            to_fp, to_session, ..
        }) => (
            false,
            format!(
                "{resource} is reserved by a handoff for {}{} — you did not get it",
                &crate::ident::name_of(to_fp),
                to_session
                    .as_ref()
                    .map(|s| format!("/{}", session_name(s)))
                    .unwrap_or_default()
            ),
            1,
        ),
        None => (
            false,
            format!(
                "{resource} is not held by anyone, including you — the claim has not \
                 converged yet; run `vox room board {room}` to check"
            ),
            1,
        ),
    };
    // **Recorded once the room has answered** (V210-79, V210-168): a session that holds it, agreed
    // or not yet, is told at its next drain if it stops holding it; one told it lost is not told
    // again that it "lapsed".
    if matches!(
        done.posting.after.fold.resources.get(&resource),
        Some(State::Held { owner, .. }) if *owner == me
    ) {
        crate::agent_hook::note_held(paths, &done.room, &done.session, &resource);
    }
    let unagreed_json: Vec<serde_json::Value> = unagreed
        .iter()
        .map(|(m, why)| serde_json::json!({"member": claim::b32(m), "why": why}))
        .collect();
    report_as(
        &done,
        claim::CLAIM,
        &resource,
        opts,
        ok,
        &said,
        code,
        Some(("unagreed", unagreed_json.into())),
    )
}

/// Why members did not agree to a claim, as one line naming each: `me` is the claimant, named
/// "you".
fn unagreed_text(me: &Digest32, unagreed: &[(Digest32, String)]) -> String {
    let name = |m: &Digest32| {
        if m == me {
            "you".to_owned()
        } else {
            // By the reader's own name for it, as every other author is (V210-162).
            format!("member {}", crate::ident::name_of(m))
        }
    };
    let mut parts: Vec<String> = unagreed
        .iter()
        .filter(|(_, why)| !why.starts_with(STAMPED_AHEAD))
        .map(|(m, why)| format!("{} {why}", name(m)))
        .collect();
    // The authors of posts the claim is stamped before, in one clause: it is one cause.
    let ahead: Vec<String> = unagreed
        .iter()
        .filter(|(_, why)| why.starts_with(STAMPED_AHEAD))
        .map(|(m, _)| name(m))
        .collect();
    if !ahead.is_empty() {
        parts.push(format!(
            "your node holds posts by {} stamped more than {} minutes ahead of your clock, and \
             your claim is stamped before them although it was made after; check the clocks",
            ahead.join(" and "),
            vox_core::node::agreestream::STAMP_LEAD_LIMIT_MILLIS / 60_000
        ));
    }
    parts.join("; ")
}

/// What a claimant must know when clocks are too far apart (V210-168): the room orders claims by
/// the stamps their nodes gave them, so the board can name a holder whose claim was made later.
fn clocks_note(unagreed: &[(Digest32, String)]) -> String {
    let mut note = String::new();
    if unagreed
        .iter()
        .any(|(_, why)| why.starts_with(CLOCKS_APART))
    {
        note.push_str(
            " While the clocks are apart, the board can name a holder whose claim was made later.",
        );
    }
    if unagreed
        .iter()
        .any(|(_, why)| why.starts_with(STAMPED_AHEAD))
    {
        note.push_str(
            " The room orders claims by their stamps, so it can order yours before a claim made \
             earlier, whose maker may have been told they hold it.",
        );
    }
    note
}

/// How a member whose clock is too far from the claimant's is described.
const CLOCKS_APART: &str = "has a clock more than";

/// How the author of a post the claim is stamped before, although made after, is described.
const STAMPED_AHEAD: &str = "made a post stamped more than";

/// The claim-protocol `type`s an agreement compares (V210-168).
const CLAIM_TYPES: &[&str] = &[
    claim::CLAIM,
    claim::RELEASE,
    claim::HANDOFF,
    claim::RENEW,
    vox_agentcomms::envelope::work::DECLINE,
];

/// How many agreement rounds a claim asks for while claim posts keep arriving between the node's
/// answer and this client's read of the same posts.
const AGREE_TRIES: usize = 3;

/// **Does every other member of the room fold this claim as `me`'s?** (V210-168)
///
/// The node asks every member it can reach whether it holds this claim, and which claim posts it
/// holds, pulls what they hold that it does not, and reports each member's set against its own
/// ([`vox_core::node::agreestream`]). Each set is folded here, as this node's own is. Returns
/// this node's fold after that, and, for every member that does not fold to `me`, why.
async fn agreement(
    paths: &Paths,
    done: &Done,
    me: &Owner,
    resource: &str,
) -> Result<(claim::Fold, Vec<(Digest32, String)>), AppError> {
    use vox_core::node::agreestream::Agreement;
    let mut client = attach(paths).await?;
    let types: Vec<String> = CLAIM_TYPES.iter().map(|t| (*t).to_owned()).collect();
    for _ in 0..AGREE_TRIES {
        let report = match client
            .request(&Request::Agree {
                channel_id: done.cid,
                entry: done.posting.entry_hash,
                types: types.clone(),
            })
            .await
        {
            Ok(Frame::Agreement { report }) => report,
            Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
            Ok(other) => return Err(crate::client::unexpected(&other)),
            Err(e) => return Err(AppError::Usage(e.to_string())),
        };
        // The node compared its posts as they were when it answered; these must be the same ones.
        let rows = coord::structured(&mut client, done.cid, CLAIM_TYPES, &[]).await?;
        if rows.len() as u64 != report.mine {
            continue;
        }
        let posted = coord::posted_of(&rows);
        let now = coord::now_millis();
        let own = claim::fold(&posted, coord::VERSION, now);
        let mut why = Vec::new();
        for (member, stands) in &report.members {
            let reason = match stands {
                Agreement::Holds { unseen, .. } if !unseen.is_empty() => {
                    Some("holds claims this node has not received".to_owned())
                }
                Agreement::Holds { absent, .. } => {
                    let theirs: Vec<Posted> = posted
                        .iter()
                        .filter(|p| !absent.contains(&p.entry_hash))
                        .cloned()
                        .collect();
                    match claim::fold(&theirs, coord::VERSION, now)
                        .resources
                        .get(resource)
                    {
                        Some(State::Held { owner, .. }) if owner == me => None,
                        Some(State::Held { owner, .. }) => {
                            Some(format!("sees {} holding it", who(owner)))
                        }
                        Some(State::Pending { .. }) => {
                            Some("sees it reserved by a handoff".to_owned())
                        }
                        None => Some("sees nobody holding it".to_owned()),
                    }
                }
                Agreement::NotReceived => Some(
                    "has not received your claim (each of you must trust the other)".to_owned(),
                ),
                Agreement::NotHeld => Some("does not count you a member of this room".to_owned()),
                Agreement::TooDifferent => {
                    Some("holds claims too different from this node's to compare".to_owned())
                }
                Agreement::Unreachable => Some("could not be reached".to_owned()),
                Agreement::Unanswered => Some("did not answer in time".to_owned()),
                Agreement::ClocksApart => Some(format!(
                    "{CLOCKS_APART} {} minutes away from yours, too far apart to order claims by; \
                     set both clocks right",
                    vox_core::node::agreestream::STAMP_LEAD_LIMIT_MILLIS / 60_000
                )),
                Agreement::StampedAhead => Some(format!(
                    "{STAMPED_AHEAD} {} minutes ahead of your clock, and your claim is stamped \
                     before it although it was made after; check both clocks",
                    vox_core::node::agreestream::STAMP_LEAD_LIMIT_MILLIS / 60_000
                )),
            };
            if let Some(r) = reason {
                why.push((*member, r));
            }
        }
        return Ok((own, why));
    }
    Err(AppError::Usage(
        "the room's claims kept changing while its members were asked; run the claim again".into(),
    ))
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
        other => (
            false,
            format!(
                "{resource} was not released: {}",
                outcome_words(other.as_ref())
            ),
        ),
    };
    report(&done, claim::RELEASE, resource, opts, ok, &said)
}

/// `vox service add`, asked of the node already running this profile (V030-06).
///
/// The one-shot form opens the profile itself, which redb refuses while a daemon holds it: a
/// person with a daemon running had to stop it, add the service, and start it again with every
/// room's passphrase. The daemon already holds the room open, so it is asked instead, and the
/// service is offered at once. It is kept as the one-shot form keeps it: offered until removed,
/// across the daemon's restarts — not withdrawn when this verb's connection closes.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or the node refuses the offer.
pub async fn service_add(
    paths: &Paths,
    room: &str,
    tag: &str,
    local: std::net::SocketAddr,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client
        .request(&Request::AddService {
            channel_id,
            service_tag: tag.to_owned(),
            local: local.to_string(),
            persist: true,
        })
        .await
    {
        Ok(Frame::Ok) => {
            // What the one-shot form says (`tunnel_cli::service_add`).
            println!(
                "vox: offering {tag:?} at {local} in room {}",
                crate::tunnel_cli::short_id_of(&channel_id)
            );
            println!("     it is dark until you `vox trust add` someone — and they join this room");
            Ok(())
        }
        // The node's reason, as `vox service add` without a daemon gives it.
        Ok(Frame::Error { reason }) => {
            Err(AppError::Usage(format!("cannot offer {tag:?}: {reason}")))
        }
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox service remove`, asked of the node already running this profile.
///
/// The one-shot form opens the profile itself, which redb refuses while a daemon holds it
/// — and a running host is exactly when removing a service matters, because that is when
/// it is carrying sessions the removal must cut (PRD-001 R22). The request is the one
/// daemon makes when a share ends; it only ever narrows what is exposed.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or the service was not offered.
pub async fn service_remove(paths: &Paths, room: &str, tag: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client
        .request(&Request::RemoveService {
            channel_id,
            service_tag: tag.to_owned(),
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: no longer offering {tag:?}; its live sessions were cut");
            Ok(())
        }
        // The node's reason, as `vox service remove` without a daemon gives it (V210-83).
        Ok(Frame::Error { reason }) => {
            Err(AppError::Usage(format!("cannot remove {tag:?}: {reason}")))
        }
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox service list`, asked of the node already running this profile (V030-24).
///
/// `add` and `remove` go to the daemon (V030-06), but `list` opened the profile itself, which
/// redb refuses while the daemon holds it: a person who had just added a service could not list
/// it. It prints what the one-shot form prints (`tunnel_cli::service_list`).
///
/// # Errors
/// If the node cannot be reached, the room is unknown, or the node cannot say.
pub async fn service_list(paths: &Paths, room: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client.request(&Request::Services { channel_id }).await {
        Ok(Frame::Services {
            room,
            services,
            shared,
        }) => {
            crate::tunnel_cli::print_services(&room, &channel_id, &services, &shared);
            Ok(())
        }
        // The node's reason, as `vox service list` without a daemon gives it.
        Ok(Frame::Error { reason }) => Err(AppError::Usage(format!(
            "cannot list that room's services: {reason}"
        ))),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
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
        let members = members_of(&mut client, cid).await?;
        crate::ident::resolve_member(to, &members, crate::ident::names())
            .map_err(|e| AppError::Usage(format!("refusing --to: {e}")))?
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
    // The fingerprint, not the word typed: a name is the poster's own and means nothing elsewhere.
    data.insert("to".into(), claim::b32(&to_fp).into());
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
        format!("handing {resource} to {}", crate::ident::name_of(&to_fp)),
    )
    .await?;
    let (ok, said) = match (&done.outcome, done.posting.after.fold.resources.get(resource)) {
        (Some(Outcome::Applied), Some(State::Pending { deadline_millis, .. })) => (
            true,
            format!(
                "{resource} is reserved for {}{} until {}; it completes when that session claims it",
                &crate::ident::name_of(&to_fp),
                to_session.map(|s| format!("/{}", session_name(s))).unwrap_or_default(),
                millis_as_time(*deadline_millis)
            ),
        ),
        (Some(Outcome::Applied), _) => (true, format!("{resource} was handed off and has since moved on")),
        (Some(Outcome::NoEffect(why)), _) => (false, format!("{resource} was not handed off: {why}")),
        (other, _) => (
            false,
            format!("{resource} was not handed off: {}", outcome_words(other.as_ref())),
        ),
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
        other => (
            false,
            format!(
                "{resource} was not declined: {}",
                outcome_words(other.as_ref())
            ),
        ),
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
        (other, _) => (
            false,
            format!(
                "{resource} was not renewed: {}",
                outcome_words(other.as_ref())
            ),
        ),
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
    // The board's position is the whole room's: its row count and newest row, which the node
    // counts rather than this reading every row (V210-120).
    let (entries, last) = if json {
        match client
            .request(&vox_core::node::ipc::Request::Count {
                channel_id: cid,
                since: None,
            })
            .await
            .map_err(|e| AppError::Usage(e.to_string()))?
        {
            vox_core::node::ipc::Frame::Count { n, last } => (n, last),
            vox_core::node::ipc::Frame::Error { reason } => return Err(AppError::Usage(reason)),
            other => return Err(crate::client::unexpected(&other)),
        }
    } else {
        (0, None)
    };
    let session = coord::session(session).unwrap_or_default();
    let me = Owner {
        author: snap.me,
        session: session.clone(),
    };
    // Each other member's lane state (ADR-028 W-3), as the node derives it from the room.
    let lanes = match client
        .request(&vox_core::node::ipc::Request::Lanes { channel_id: cid })
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?
    {
        vox_core::node::ipc::Frame::Lanes { lanes } => lanes,
        vox_core::node::ipc::Frame::Error { reason } => return Err(AppError::Usage(reason)),
        other => return Err(crate::client::unexpected(&other)),
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
                "lanes": lanes
                    .iter()
                    .map(|(m, state)| serde_json::json!({
                        "member": claim::b32(m),
                        "state": state,
                    }))
                    .collect::<Vec<_>>(),
                "position": {
                    // A cursor, so never a message not received yet (V030-10): the node's
                    // `last` is the row that arrived last.
                    "entries": entries,
                    "last": last.map(|h| claim::b32(&h)),
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
                format!("{}\t{}{mine}{expiry}", name(resource), who(owner))
            }
            State::Pending {
                from,
                to_fp,
                to_session,
                deadline_millis,
                ..
            } => format!(
                "{}\tpending handoff from {} to {}{}{} (lapses in {}s)",
                name(resource),
                who(from),
                &crate::ident::name_of(to_fp),
                to_session
                    .as_ref()
                    .map(|s| format!("/{}", session_name(s)))
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
    // The lanes (ADR-028 W-3): one line per other member, by your name for it, and its state.
    if !lanes.is_empty() {
        writeln!(out, "lanes:").map_err(AppError::Io)?;
        for (member, state) in &lanes {
            writeln!(out, "  {}\t{state}", crate::ident::name_of(member)).map_err(AppError::Io)?;
        }
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
pub(crate) const FILE: &str = vox_core::node::shares::FILE;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// An offer read off the room's log.
struct Offer {
    /// The announcement's entry.
    entry: Digest32,
    /// When it was announced, seconds, never later than now.
    created: u64,
    author: Digest32,
    name: String,
    size: u64,
    sha256: String,
    tag: String,
    /// Served over HTTP, as `vox share` serves; an announcement without it is answered with the
    /// raw bytes.
    http: bool,
}

/// `vox room get` — collect an offered file and verify it.
///
/// **Where it lands is the receiver's decision, never the sender's** (PRD-001 R18, D4). The
/// offer's `name` is text another member wrote, and it used to become the path as written:
/// `../../.ssh/authorized_keys` or `/etc/…` was honoured, `File::create` truncated whatever was
/// there before a single byte was verified, and a mismatch then *deleted* it. Now:
///
/// - the file goes into the node's files directory for the room, `<data root>/nodes/<node>/files/
///   <room>/` (ADR-028 F-4), or `--dir` when the person names another, under the sender's name
///   reduced to a bare file name ([`safe_file_name`]); `--out` names an exact path instead.
///   Nothing is written outside the node's files directory unless the person asked for it here;
/// - **nothing that exists is ever overwritten**: a taken name gets a ` (1)`, ` (2)` … suffix,
///   and an `--out` that exists is refused;
/// - the bytes go to a hidden `.part` file beside it, and only a transfer whose SHA-256 and size
///   match the announcement is linked into place; anything else removes the `.part` and nothing
///   else.
///
/// # Errors
/// If the node cannot be reached, the room is unknown, no matching offer exists, the
/// destination is unusable, the transfer cannot be established, stalls, sends more than was
/// announced, or **does not match the announced hash** — in every one of which nothing is left
/// behind and nothing that was there before is touched.
pub async fn get_file(
    paths: &Paths,
    room: &str,
    selector: &str,
    dir: Option<&std::path::Path>,
    out: Option<&std::path::Path>,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let rows = match client.read_rows(channel_id, None).await {
        Ok(Frame::Rows { rows }) => rows,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };

    // Newest first: re-offering a file supersedes. But **an offer that has ended does not
    // hide one that is still served** (V210-84): each offer has a tag of its own, so the newest
    // match may be one whose share has stopped while an older offer of the same file
    // still runs. So the older offers are tried in turn — but only those of **the same file
    // from the same member** as the newest match: same author, same SHA-256. A fallback to
    // anything else would hand over a different file that only shares a name.
    let mut offers: Vec<Offer> = Vec::new();
    // Older matches outside that group — a different file, or the same file from another
    // member. Never collected in its place; if the get fails, the live ones are named in the
    // error by their exact tag, which selects exactly that offer.
    let mut others: Vec<Offer> = Vec::new();
    for r in rows.iter().rev() {
        let Ok(env) = Envelope::parse(&r.text) else {
            continue;
        };
        if env.kind != FILE {
            continue;
        }
        let d = &env.data;
        let field = |k: &str| d.get(k).and_then(|v| v.as_str()).map(str::to_owned);
        let (Some(name), Some(sha256), Some(tag), Some(size)) = (
            field("name"),
            field("sha256"),
            field("tag"),
            d.get("size").and_then(serde_json::Value::as_u64),
        ) else {
            continue;
        };
        let http = d
            .get("http")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let matches = name == selector || sha256.starts_with(selector) || tag == selector;
        if !matches || offers.iter().any(|o| o.author == r.author && o.tag == tag) {
            continue;
        }
        let offer = Offer {
            entry: r.entry_hash,
            created: (r.created_millis / 1000).min(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            ),
            author: r.author,
            name,
            size,
            sha256,
            tag,
            http,
        };
        match offers.first() {
            Some(newest) if newest.author != offer.author || newest.sha256 != offer.sha256 => {
                if others.len() < MAX_OFFERS_TRIED {
                    others.push(offer);
                }
                continue;
            }
            _ => offers.push(offer),
        }
        // Each try that is not served costs a dial; this many is past any real case of one
        // file offered again while an older offer of it still runs.
        if offers.len() == MAX_OFFERS_TRIED {
            break;
        }
    }
    if offers.is_empty() {
        return Err(AppError::Usage(format!(
            "no offer in this room matches {selector:?} — `vox room read` shows what was \
             announced"
        )));
    }

    let mut first_error = None;
    let tried = offers.len();
    for (i, offer) in offers.iter().enumerate() {
        let result = collect_offer(&mut client, paths, channel_id, offer, dir, out).await;
        match result {
            Ok(()) => return Ok(()),
            Err(e) => {
                if i + 1 < tried {
                    eprintln!(
                        "vox: the offer {} of {} was not collected ({e}); trying an older offer \
                         of it",
                        offer.tag, offer.name
                    );
                }
                first_error.get_or_insert(e);
            }
        }
    }
    let Some(e) = first_error else {
        return Err(AppError::Usage(format!(
            "no offer matching {selector:?} was tried"
        )));
    };
    // The other matches that are still served, newest first, one per member and file: a
    // suggestion that names an ended offer, or that a selector would redirect to the ended
    // newest match, is a command that fails.
    let newest = &offers[0];
    let mut live: Vec<&Offer> = Vec::new();
    for o in &others {
        if live
            .iter()
            .any(|l| l.author == o.author && l.sha256 == o.sha256)
        {
            continue;
        }
        if offer_is_live(&mut client, channel_id, o).await {
            live.push(o);
        }
    }
    if tried == 1 && live.is_empty() {
        return Err(e);
    }
    let mut said = if tried > 1 {
        format!(
            "{e} (and {} older offer{} of it could not be collected either)",
            tried - 1,
            if tried > 2 { "s" } else { "" }
        )
    } else {
        e.to_string()
    };
    // Say what else answers to the selector and is served, and how to ask for exactly it,
    // rather than silently collecting it instead.
    for o in live {
        use std::fmt::Write as _;
        let short = &o.sha256[..o.sha256.len().min(16)];
        let who = crate::ident::name_of(&o.author);
        if o.sha256 == newest.sha256 {
            let _ = write!(
                said,
                "\n       the same file is also offered by {who}: `vox room get {room} {}`",
                o.tag
            );
        } else {
            let _ = write!(
                said,
                "\n       a different file also matches {selector:?}: {} ({} bytes, sha256 \
                 {short}, offered by {who}) — collect exactly it with `vox room get {room} {}`",
                o.name, o.size, o.tag
            );
        }
    }
    Err(AppError::Usage(said))
}

/// Whether `offer` is still served: forwarded to, it sends its first byte. An ended offer is
/// refused by its host and the connection closes without one. An empty file sends nothing
/// either way, so one is taken as served when the connection is accepted and ends cleanly.
async fn offer_is_live(client: &mut IpcClient, channel_id: Digest32, offer: &Offer) -> bool {
    use tokio::io::AsyncReadExt as _;
    const PROBE: std::time::Duration = std::time::Duration::from_secs(10);
    let Ok(Frame::Bound { local }) = client
        .request(&Request::Forward {
            channel_id,
            host: offer.author,
            service_tag: offer.tag.clone(),
            local: "127.0.0.1:0".into(),
        })
        .await
    else {
        return false;
    };
    let answered = async {
        let mut sock = tokio::net::TcpStream::connect(&local).await.ok()?;
        // A `vox share` offer is HTTP: it answers once asked, as `receive` asks.
        if offer.http {
            use tokio::io::AsyncWriteExt as _;
            let req = format!(
                "GET /{} HTTP/1.1\r\nHost: vox\r\nConnection: close\r\n\r\n",
                offer.name
            );
            sock.write_all(req.as_bytes()).await.ok()?;
        }
        let mut byte = [0u8; 1];
        sock.read(&mut byte).await.ok()
    };
    let live = match tokio::time::timeout(PROBE, answered).await {
        Ok(Some(n)) => n > 0 || offer.size == 0,
        _ => false,
    };
    let _ = client.request(&Request::StopForward { local }).await;
    live
}

/// The most matching offers `vox room get` tries, newest first (V210-84).
const MAX_OFFERS_TRIED: usize = 16;

/// Collect one offer: choose where it lands, forward to it, transfer, verify.
async fn collect_offer(
    client: &mut IpcClient,
    paths: &Paths,
    channel_id: Digest32,
    offer: &Offer,
    dir: Option<&std::path::Path>,
    out: Option<&std::path::Path>,
) -> Result<(), AppError> {
    let managed = out.is_none() && dir.is_none();
    let dest = match out {
        Some(exact) => {
            if exact.symlink_metadata().is_ok() {
                return Err(AppError::Usage(format!(
                    "{} already exists; `vox room get` never overwrites a file — choose \
                     another --out, or leave it out to use the download directory",
                    exact.display()
                )));
            }
            Destination::Exact(exact.to_owned())
        }
        None => {
            let dir = match dir {
                Some(d) => {
                    std::fs::create_dir_all(d).map_err(|e| {
                        AppError::Usage(format!("cannot use {} for the file: {e}", d.display()))
                    })?;
                    d.to_owned()
                }
                None => {
                    let d = vox_core::node::pulls::room_dir(paths, &channel_id);
                    vox_core::node::paths::create_private_dir(&d).map_err(|e| {
                        AppError::Usage(format!("cannot use {} for the file: {e}", d.display()))
                    })?;
                    d
                }
            };
            Destination::Into(dir, safe_file_name(&offer.name))
        }
    };

    // **A pull never fills the disk** (ADR-028 F-3): one that would leave less than the reserve
    // free is refused before anything is dialled.
    if let Some(why) = vox_core::node::pulls::short_of_space(&dest.dir(), offer.size) {
        return Err(AppError::Usage(format!(
            "refusing to pull {} ({}): {why}",
            safe_file_name(&offer.name),
            vox_core::node::pulls::bytes(offer.size)
        )));
    }

    // **Why a transfer failed is the node's to say** (ADR-020 11.8): followed from before the
    // forward opens, so its refusal is not missed.
    let mut events = match crate::client::one_shot(paths) {
        Ok(at) => crate::client::events(&at).await.ok(),
        Err(_) => None,
    };
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
        // The sender was reached and is serving; this member's connection to it is full. Which
        // tunnels hold it is said too, from the node's own list (`vox status`).
        Ok(Frame::Error { reason })
            if reason == vox_core::node::api::Fault::TunnelLimit.explain() =>
        {
            let open = tunnels_to(paths, &offer.author).await;
            return Err(AppError::Usage(format!(
                "cannot collect the offer: {reason}{}",
                if open.is_empty() {
                    String::new()
                } else {
                    format!("\n       open to it now: {}", open.join(", "))
                }
            )));
        }
        Ok(Frame::Error { reason }) => {
            return Err(AppError::Usage(format!(
                "cannot reach the offer: {reason} — the sender may have stopped serving it, or \
                 may not have trusted this identity"
            )));
        }
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };

    let result = collect(&bound, &dest, offer).await.and_then(|placed| {
        // **A copy in the node's files directory ends with its message** (ADR-028 F-5): it is
        // recorded so the daemon deletes it then. One the person put elsewhere is theirs.
        if managed {
            vox_core::node::pulls::record(
                paths,
                &vox_core::node::pulls::Pulled {
                    room: channel_id,
                    entry: offer.entry,
                    path: placed,
                    created: offer.created,
                },
            )
            .map_err(|e| {
                AppError::Usage(format!("the file landed, but cannot be recorded: {e}"))
            })?;
        }
        Ok(())
    });
    let _ = client
        .request(&Request::StopForward {
            local: bound.clone(),
        })
        .await;
    match result {
        // **An offer its sharer no longer serves is gone, and is said to be** (ADR-020 11.8): the
        // announcement stays on the log, the bytes were live only while it was shared. A transfer
        // the sharer refused says that, not the socket's error ("Connection reset by peer"). One
        // that sent the wrong bytes says that, whatever the node said.
        Err(e) if !e.to_string().contains("announced") => match events.as_mut() {
            Some(ev) => Err(why_not_collected(ev, offer).await.unwrap_or(e)),
            None => Err(e),
        },
        other => other,
    }
}

/// What the node said about a transfer of `offer` that failed, within a moment of it: the
/// sharer withdrew it mid-transfer (the transfer's stream was reset; this says why), refused it
/// (it no longer serves the offer: this node reads the announcement, so the sharer trusted it),
/// or could not be reached. `None` if it said none of these.
async fn why_not_collected(events: &mut IpcClient, offer: &Offer) -> Option<AppError> {
    use vox_core::node::api::NodeEvent;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while let Ok(Ok(Some(frame))) = tokio::time::timeout_at(deadline, events.next()).await {
        let Frame::Event(NodeEvent::ProxyRefused { reason }) = frame else {
            continue;
        };
        if !reason.contains(&offer.tag) {
            continue;
        }
        let who = crate::ident::name_of(&offer.author);
        return Some(AppError::Usage(if reason.contains("withdrew access") {
            // Reached, and serving it a moment ago: the sharer stopped sharing mid-transfer.
            format!(
                "the offer of {} was withdrawn while it was being collected: {who} stopped \
                 sharing it ({reason}). The file is served only while {who} shares it; ask them \
                 to share it again",
                offer.name
            )
        } else if reason.contains("the host refused") {
            format!(
                "the offer of {} is gone: {who} no longer serves it. The announcement stays in \
                 the room, but the file is served only while {who} shares it; ask them to share \
                 it again",
                offer.name
            )
        } else {
            format!(
                "the offer of {} cannot be collected now: {who} could not be reached ({reason}). \
                 The file is served only while {who} is online and sharing it",
                offer.name
            )
        }));
    }
    None
}

/// Where a collected file is to land.
enum Destination {
    /// Into this directory, under this (already safe) name or the first free variant of it.
    Into(std::path::PathBuf, String),
    /// Exactly here, and only if nothing is.
    Exact(std::path::PathBuf),
}

impl Destination {
    /// The directory the `.part` file goes in: beside the destination, so the final step is
    /// a link on one filesystem and never a copy.
    fn dir(&self) -> std::path::PathBuf {
        match self {
            Destination::Into(dir, _) => dir.clone(),
            Destination::Exact(p) => p
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .map_or_else(|| std::path::PathBuf::from("."), Path::to_owned),
        }
    }

    /// A name for the `.part` file.
    fn stem(&self) -> String {
        match self {
            Destination::Into(_, name) => name.clone(),
            Destination::Exact(p) => p.file_name().map_or_else(
                || "download".to_owned(),
                |n| n.to_string_lossy().into_owned(),
            ),
        }
    }
}

use vox_core::node::pulls::numbered;
pub use vox_core::node::pulls::safe_file_name;

/// How long one read of the transfer may wait before the transfer is abandoned. A sender
/// that has gone quiet must not hold the collector for ever.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Stream the offered bytes to a `.part` file beside `dest`, verify them, and only then link
/// them into place under a name nothing else holds.
async fn collect(
    bound: &str,
    dest: &Destination,
    offer: &Offer,
) -> Result<std::path::PathBuf, AppError> {
    let dir = dest.dir();
    // `create_new`, so the temporary file is never somebody else's either.
    let (part, file) = (0..1000)
        .find_map(|n| {
            let p = dir.join(format!(".{}.{}-{n}.part", dest.stem(), std::process::id()));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&p)
                .ok()
                .map(|f| (p, f))
        })
        .ok_or_else(|| {
            AppError::Usage(format!(
                "cannot create a temporary file in {}",
                dir.display()
            ))
        })?;
    let result = receive(bound, file, &dir, offer).await;
    let total = match result {
        Ok(total) => total,
        Err(e) => {
            // **Only the `.part` is removed.** It is the one file this collector created;
            // whatever was in the directory before is not its to delete.
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
    };
    let placed = place(&part, dest);
    let _ = std::fs::remove_file(&part);
    let placed = placed?;
    println!(
        "vox: {} ({total} bytes) matches its announced SHA-256",
        placed.display()
    );
    Ok(placed)
}

/// Link a verified `.part` into place without replacing anything.
///
/// A hard link fails if the name is taken, which makes "is it free" and "take it" one step
/// — a rename would silently replace whatever appeared in between.
fn place(part: &Path, dest: &Destination) -> Result<std::path::PathBuf, AppError> {
    match dest {
        Destination::Exact(p) => std::fs::hard_link(part, p)
            .map(|()| p.clone())
            .map_err(|e| {
                AppError::Usage(format!(
                    "cannot put the file at {}: {e}; nothing was overwritten",
                    p.display()
                ))
            }),
        Destination::Into(dir, name) => {
            for n in 0..1000 {
                let candidate = dir.join(numbered(name, n));
                match std::fs::hard_link(part, &candidate) {
                    Ok(()) => return Ok(candidate),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => {
                        return Err(AppError::Usage(format!(
                            "cannot put the file at {}: {e}",
                            candidate.display()
                        )))
                    }
                }
            }
            Err(AppError::Usage(format!(
                "every name from {name} to {} is taken in {}",
                numbered(name, 999),
                dir.display()
            )))
        }
    }
}

/// Read the transfer into `file`, refusing more bytes than were announced, a stall, and any
/// result whose SHA-256 is not the announced one. Returns the byte count.
async fn receive(
    bound: &str,
    mut file: std::fs::File,
    dir: &std::path::Path,
    offer: &Offer,
) -> Result<u64, AppError> {
    // **A pull never fills the disk** (ADR-028 F-3): it stops below the reserve.
    let mut since = 0u64;
    use sha2::{Digest as _, Sha256};
    use tokio::io::AsyncReadExt as _;

    let mut sock = tokio::time::timeout(READ_TIMEOUT, tokio::net::TcpStream::connect(bound))
        .await
        .map_err(|_| AppError::Usage("the forward did not answer".into()))?
        .map_err(|e| AppError::Usage(format!("connecting to the forward: {e}")))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    if offer.http {
        use tokio::io::AsyncWriteExt as _;
        let req = format!(
            "GET /{} HTTP/1.1\r\nHost: vox\r\nConnection: close\r\n\r\n",
            offer.name
        );
        sock.write_all(req.as_bytes())
            .await
            .map_err(|e| AppError::Usage(format!("asking for the file: {e}")))?;
        // Skip the response head; whatever follows it is the body.
        let mut head = Vec::new();
        let body_start = loop {
            let n = sock
                .read(&mut buf)
                .await
                .map_err(|e| AppError::Usage(format!("reading the reply: {e}")))?;
            if n == 0 {
                return Err(AppError::Usage("the sharer closed before answering".into()));
            }
            head.extend_from_slice(&buf[..n]);
            if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            if head.len() > 16 * 1024 {
                return Err(AppError::Usage("the sharer's reply is not HTTP".into()));
            }
        };
        if !head.starts_with(b"HTTP/1.1 200") && !head.starts_with(b"HTTP/1.0 200") {
            return Err(AppError::Usage("the sharer refused the request".into()));
        }
        let rest = &head[body_start..];
        hasher.update(rest);
        std::io::Write::write_all(&mut file, rest)
            .map_err(|e| AppError::Usage(format!("writing the download: {e}")))?;
        total += rest.len() as u64;
    }
    loop {
        let n = tokio::time::timeout(READ_TIMEOUT, sock.read(&mut buf))
            .await
            .map_err(|_| {
                AppError::Usage(format!(
                    "the transfer stalled for {}s after {total} of {} bytes; nothing was kept",
                    READ_TIMEOUT.as_secs(),
                    offer.size
                ))
            })?
            .map_err(|e| AppError::Usage(format!("reading the transfer: {e}")))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > offer.size {
            return Err(AppError::Usage(format!(
                "the sender sent more than the {} bytes it announced; nothing was kept",
                offer.size
            )));
        }
        vox_core::node::pulls::still_room(dir, &mut since, n as u64)
            .map_err(|e| AppError::Usage(format!("{e}; nothing was kept")))?;
        hasher.update(&buf[..n]);
        std::io::Write::write_all(&mut file, &buf[..n])
            .map_err(|e| AppError::Usage(format!("writing the download: {e}")))?;
    }
    file.sync_all()
        .map_err(|e| AppError::Usage(format!("flushing the download: {e}")))?;
    drop(file);

    let got = hex(&hasher.finalize());
    if got != offer.sha256 || total != offer.size {
        // **Nothing is kept.** `cat | nc` truncating silently is the classic way this idiom
        // bites; a file that looks complete and is not would reproduce exactly that failure
        // with extra steps. The caller removes the `.part`, which is all there is.
        return Err(AppError::Usage(format!(
            "the transfer does not match what was announced — expected sha256 {} over {} bytes, \
             got {got} over {total}. Nothing was kept.",
            offer.sha256, offer.size
        )));
    }
    Ok(total)
}

/// A room passphrase from `--passphrase-file` (`-` reads stdin), stripping exactly one trailing
/// newline; else asked for at the terminal, twice when `confirm`.
///
/// Never an argument: argv is visible to anything that can run `ps`. **Never stdin unasked**
/// (V210-165): this read stdin to its end whenever there was no `--passphrase-file`, and an
/// agent's harness leaves stdin open and writes nothing, so the command waited for ever, saying
/// nothing. Without a terminal and without the flag it fails at once, saying how to give it.
fn room_passphrase(
    file: Option<&std::path::Path>,
    what: &str,
    confirm: bool,
) -> Result<String, AppError> {
    let Some(path) = file else {
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            return Err(AppError::Usage(format!(
                "this needs {what}, and there is no terminal to ask at.\n\
                 \x20      {}",
                crate::tunnel_cli::GIVE_ROOM_PASSPHRASE
            )));
        }
        let first = crate::tunnel_cli::prompt_passphrase("room passphrase")?;
        if confirm && crate::tunnel_cli::prompt_passphrase("again")? != first {
            return Err(AppError::Usage(
                "the two passphrases differ; nothing was done".into(),
            ));
        }
        return Ok(crate::tunnel_cli::encouraged(first, "room"));
    };
    let buf = crate::tunnel_cli::passphrase_file_text(path)?;
    let p = buf
        .strip_suffix('\n')
        .unwrap_or(&buf)
        .strip_suffix('\r')
        .unwrap_or_else(|| buf.strip_suffix('\n').unwrap_or(&buf));
    // **An empty file or stdin gives an empty passphrase on purpose** (V030-36, decider
    // 2026-10-02: "technically optional"). It said "expected … and it is empty" and stopped. No
    // `--passphrase-file` at all is still not one: that asks, or fails without a terminal.
    Ok(crate::tunnel_cli::encouraged(p, "room").to_owned())
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
pub async fn join(
    paths: &Paths,
    link: &str,
    passphrase_file: Option<&std::path::Path>,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    // A room this node holds open, and has not left, is not joined again: its address is taken
    // as where the room's host is now, and the host is dialled there (V210-167). No passphrase is read for it: none
    // is used.
    let held = match vox_core::node::link::InviteLink::parse(link) {
        Ok(parsed) => rooms_of(&mut client)
            .await?
            .into_iter()
            // A room this identity left is not: it is joined again, with its passphrase, from
            // scratch (V030-08).
            .find(|(id, _, open, over)| *id == parsed.channel_id && *open && over != "left")
            .map(|(id, name, _, _)| {
                if name.is_empty() {
                    b32_encode(&id)
                } else {
                    name
                }
            }),
        Err(_) => None,
    };
    if let Some(name) = held {
        return match client
            .request(&Request::Join {
                link: link.to_owned(),
                passphrase: zeroize::Zeroizing::new(String::new()),
            })
            .await
        {
            Ok(Frame::Ok) => {
                println!(
                    "vox: this node already holds {name}; a member answered at the address \
                     given, so it is kept as where the room's host is now"
                );
                Ok(())
            }
            Ok(Frame::Error { reason }) if reason.starts_with("Failed(Unreachable)") => {
                Err(AppError::Usage(format!(
                    "this node already holds {name}, and nobody answered at the address given; \
                     nothing was changed{}",
                    crate::tunnel_cli::join_detail(&reason)
                )))
            }
            Ok(Frame::Error { reason }) => Err(AppError::Usage(format!(
                "this node already holds {name}; nothing was changed{}",
                crate::tunnel_cli::join_detail(&reason)
            ))),
            Ok(other) => Err(crate::client::unexpected(&other)),
            Err(e) => Err(AppError::Usage(e.to_string())),
        };
    }
    let passphrase = room_passphrase(passphrase_file, "the room's passphrase", false)?;
    match client
        .request(&Request::Join {
            link: link.to_owned(),
            passphrase: zeroize::Zeroizing::new(passphrase),
        })
        .await
    {
        Ok(Frame::Ok) => {
            // The room's own name, as a member told it (ADR-028 R-1): the joiner names nothing.
            let joined = match vox_core::node::link::InviteLink::parse(link) {
                Ok(parsed) => rooms_of(&mut client)
                    .await?
                    .into_iter()
                    .find(|(id, _, _, _)| *id == parsed.channel_id)
                    .map(|(id, name, _, _)| {
                        vox_core::node::resolver::room_shown(Some(name.as_str()), &id)
                    }),
                Err(_) => None,
            };
            println!("vox: joined {}", joined.as_deref().unwrap_or("the room"));
            println!("     you read a member once you trust it and it trusts you: `vox trust add`");
            Ok(())
        }
        // The daemon sends the outcome's name; turn it into the same guidance `vox connect`
        // gives, so a wrong passphrase is not reported as `Failed(Refused)`.
        Ok(Frame::Error { reason }) => Err(AppError::Usage(
            match crate::tunnel_cli::fault_named(&reason) {
                Some(fault) => format!(
                    "cannot join: {}{}",
                    crate::tunnel_cli::join_advice_after(Some(fault), &reason),
                    crate::tunnel_cli::join_detail(&reason)
                ),
                None => format!("cannot join: {reason}"),
            },
        )),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room create` — create a room over a running node.
///
/// # Errors
/// If the node cannot be reached or the create is refused.
pub async fn create(
    paths: &Paths,
    name: &str,
    passphrase_file: Option<&std::path::Path>,
    idle_end: Option<&str>,
) -> Result<(), AppError> {
    // Every member sees the room under this name, and it is the room part of every service
    // address in it: one DNS label (ADR-028 R-1, R-2). Said before a passphrase is asked for.
    let name = vox_core::governance::name::room_name(name)
        .map_err(|why| AppError::Usage(format!("cannot create the room: {why}")))?;
    // Checked before anything is made: a typo must not leave a room with no idle end behind.
    let idle_secs = match idle_end {
        None => None,
        Some(text) => match vox_core::node::retention::parse_duration(text) {
            Some(s) if s > 0 => Some(s),
            _ => {
                return Err(AppError::Usage(format!(
                    "{text:?} is not an idle end: use 1h, 1w, 1m (a month), or a number of seconds"
                )))
            }
        },
    };
    let passphrase = room_passphrase(passphrase_file, "a passphrase for the new room", true)?;
    let mut client = attach(paths).await?;
    let before: Vec<Digest32> = match idle_secs {
        Some(_) => rooms_of(&mut client)
            .await?
            .into_iter()
            .map(|(id, _, _, _)| id)
            .collect(),
        None => Vec::new(),
    };
    match client
        .request(&Request::Create {
            name: name.clone(),
            passphrase: zeroize::Zeroizing::new(passphrase),
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: created {name}");
            if let Some(idle_secs) = idle_secs {
                let made = rooms_of(&mut client)
                    .await?
                    .into_iter()
                    .map(|(id, _, _, _)| id)
                    .find(|id| !before.contains(id))
                    .ok_or_else(|| {
                        AppError::Usage(
                            "the room was created, but this node does not list it, so its idle end was not set"
                                .into(),
                        )
                    })?;
                match client
                    .request(&Request::IdleEnd {
                        channel_id: made,
                        idle_secs,
                    })
                    .await
                {
                    Ok(Frame::Ok) => println!(
                        "     it ends by itself after {} with nothing said in it",
                        vox_core::node::retention::describe(idle_secs)
                    ),
                    Ok(Frame::Error { reason }) => {
                        return Err(AppError::Usage(format!(
                            "the room was created, but its idle end was not set: {reason}"
                        )))
                    }
                    Ok(other) => return Err(crate::client::unexpected(&other)),
                    Err(e) => return Err(AppError::Usage(e.to_string())),
                }
            }
            println!("     `vox room list` shows its id; that id is what agents pass as --room");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(format!("cannot create: {reason}"))),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room rename` — give a room a new name, for every member (ADR-028 R-1).
///
/// # Errors
/// A name that is not one DNS label, an unreachable node, an unknown room, a wrong identity
/// passphrase, or a caller who is not the room's creator or an admin.
pub async fn rename(
    paths: &Paths,
    room: &str,
    name: &str,
    identity_passphrase: &str,
) -> Result<(), AppError> {
    let name = vox_core::governance::name::room_name(name)
        .map_err(|why| AppError::Usage(format!("cannot rename the room: {why}")))?;
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client
        .request(&Request::RenameRoom {
            channel_id,
            name: name.clone(),
            identity_passphrase: zeroize::Zeroizing::new(identity_passphrase.to_owned()),
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!("vox: renamed {} to {name}", short(&channel_id));
            println!("     every member sees the new name as this reaches them");
            Ok(())
        }
        // The node's own words (`Fault::explain`) say why: not an admin, or not a name.
        Ok(Frame::Error { reason }) => {
            Err(AppError::Usage(format!("cannot rename the room: {reason}")))
        }
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room retention` — set how long the room keeps messages (ADR-023 decision 2).
///
/// # Errors
/// An unparseable duration, an unreachable node, an unknown room, a wrong identity
/// passphrase, or a caller who is not the room's admin.
pub async fn retention(
    paths: &Paths,
    room: &str,
    duration: &str,
    identity_passphrase: &str,
) -> Result<(), AppError> {
    let ttl = vox_core::node::retention::parse_duration(duration).ok_or_else(|| {
        AppError::Usage(format!(
            "{duration:?} is not a retention: use 1h, 1w, 1m (a month), a number of seconds, \
             or forever"
        ))
    })?;
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client
        .request(&Request::SetRetention {
            channel_id,
            ttl,
            identity_passphrase: zeroize::Zeroizing::new(identity_passphrase.to_owned()),
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!(
                "vox: {} keeps messages {}",
                short(&channel_id),
                match ttl {
                    0 => "forever".to_owned(),
                    t => format!("for {}", vox_core::node::retention::describe(t)),
                }
            );
            if ttl > 0 {
                println!(
                    "     older messages are removed now, on every member as this reaches them"
                );
                println!(
                    "     a modified node can keep everything: this is not a security property"
                );
            }
            Ok(())
        }
        // A member who is not the room's creator or an admin set only their own node's (V030-32).
        Ok(Frame::OwnRetention { own, room }) => {
            let say = |t: u64| match t {
                0 => "forever".to_owned(),
                t => format!("for {}", vox_core::node::retention::describe(t)),
            };
            if own == room {
                println!(
                    "vox: you follow the room's retention for {} again: this node keeps its \
                     messages {}",
                    short(&channel_id),
                    say(own)
                );
            } else {
                println!(
                    "vox: set your own retention for {}: this node keeps its messages {}",
                    short(&channel_id),
                    say(own)
                );
            }
            println!(
                "     the room's is {}, and only its creator or an admin changes that; nothing \
                 changed for anyone else",
                match room {
                    0 => "forever".to_owned(),
                    t => vox_core::node::retention::describe(t),
                }
            );
            Ok(())
        }
        // The node's own words (`Fault::explain`) say why — including a member asking to keep
        // the room's messages longer than the room does, which has its own fault.
        Ok(Frame::Error { reason }) => {
            Err(AppError::Usage(format!("cannot set retention: {reason}")))
        }
        Ok(other) => Err(crate::client::unexpected(&other)),
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
pub async fn link(paths: &Paths, room: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client.request(&Request::Invite { channel_id }).await {
        Ok(Frame::Link { url, note }) => {
            println!("{url}");
            if !note.is_empty() {
                eprintln!("vox: {note}");
            }
            eprintln!("vox: send the passphrase another way than this address (in person, a call, a different app)");
            eprintln!("     joining grants nothing — use `vox trust add` to decide who reads you");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

// ---------------------------------------------------------------- the trust keyring

/// Send a keyring change, giving the identity passphrase only when the node says it needs it
/// (V210-159): within 30 minutes of its last entry none is needed. `given` is what the command line
/// gave (`--identity-passphrase-file`, `VOX_IDENTITY_PASSPHRASE`); it is sent at once, and a right
/// one starts the window again. With none given and the window passed, it is asked for at the
/// terminal and the change sent again; with no terminal, the node's reason is the answer.
async fn keyring_change(
    client: &mut IpcClient,
    given: Option<String>,
    request: impl Fn(zeroize::Zeroizing<String>) -> Request,
) -> Result<Frame, AppError> {
    let asked = given.is_none();
    let reply = client
        .request(&request(zeroize::Zeroizing::new(given.unwrap_or_default())))
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?;
    let needed = vox_core::node::api::Fault::PassphraseNeeded.explain();
    match reply {
        Frame::Error { reason }
            if asked && reason == needed && std::io::IsTerminal::is_terminal(&std::io::stdin()) =>
        {
            eprintln!("vox: {}", reason.lines().next().unwrap_or_default());
            let passphrase = crate::tunnel_cli::ask_identity_passphrase()?;
            client
                .request(&request(zeroize::Zeroizing::new(passphrase)))
                .await
                .map_err(|e| AppError::Usage(e.to_string()))
        }
        other => Ok(other),
    }
}

/// `vox trust add`, asked of the running node instead of a second one.
pub async fn trust_add(
    paths: &Paths,
    target: Digest32,
    petname: &str,
    given: Option<String>,
    full_history: bool,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    crate::ident::check_new_name(crate::ident::names(), &target, petname)?;
    match keyring_change(&mut client, given, |identity_passphrase| Request::Trust {
        target,
        petname: petname.to_owned(),
        identity_passphrase,
        full_history,
    })
    .await
    {
        Ok(Frame::Ok) => {
            println!(
                "vox: trusting {} as {petname:?}",
                crate::ident::author_id(&target)
            );
            if full_history {
                println!("     with full history: it may also read what you wrote before now");
            }
            println!("     it may now read what you write in every room you share — now and later");
            println!("     and you read what it writes, once it trusts you too");
            println!("     and reach every service you bind to a room you are both in");
            println!("     `vox trust remove` undoes it and changes the lock everywhere");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(e),
    }
}

/// `vox trust rename`, asked of the running node: only an identity already trusted. A keyring
/// change, so the identity passphrase is asked for only when the node says it is needed
/// (V210-159), as `vox trust add` and `remove` do.
pub async fn trust_rename(
    paths: &Paths,
    fingerprint: &str,
    name: &str,
    given: Option<String>,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    // A read, so no passphrase (V210-165).
    let entries = match client.trusted("").await {
        Ok(Frame::Trusted { entries }) => entries,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let ids: Vec<Digest32> = entries.iter().map(|(id, _)| *id).collect();
    let target = resolve_prefix(fingerprint, &ids).map_err(|_| {
        AppError::Usage(format!(
            "no trusted identity matches {fingerprint:?}, so there is nothing to rename — \
             `vox trust add` it first"
        ))
    })?;
    crate::ident::check_new_name(&entries, &target, name)?;
    match keyring_change(&mut client, given, |identity_passphrase| Request::Rename {
        target,
        petname: name.to_owned(),
        identity_passphrase,
    })
    .await
    {
        Ok(Frame::Ok) => {
            println!(
                "vox: {} is now {name:?} — its services are reachable as \
                 <service>.{}.<room>.vox",
                short(&target),
                vox_core::node::resolver::label_of(name)
            );
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(e),
    }
}

/// `vox trust remove`, asked of the running node.
pub async fn trust_remove(
    paths: &Paths,
    target: Digest32,
    given: Option<String>,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    match keyring_change(&mut client, given, |identity_passphrase| Request::Untrust {
        target,
        identity_passphrase,
    })
    .await
    {
        Ok(Frame::Ok) => {
            println!(
                "vox: no longer trusting {}",
                crate::ident::author_id(&target)
            );
            println!("     your sender key is rotated and everyone still trusted is re-keyed");
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(e),
    }
}

/// `vox trust list`, asked of the running node: a read, so no passphrase (V210-165).
pub async fn trust_list(paths: &Paths) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    match client.trusted("").await {
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
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox id`: this node's fingerprint, from the daemon when the node is attached, else from its
/// files; a node with no identity has one made first (ADR-026 C-5).
///
/// Printing your own fingerprint is the most ordinary thing a person does — it is what they send
/// to somebody who will type it into `vox trust add` — and it needs no secret and changes nothing,
/// so it starts no daemon and attaches nothing.
///
/// # Errors
/// The node's files cannot be read, or a new identity's passphrase cannot be had.
pub fn print_identity(
    paths: &Paths,
    flag: Option<String>,
    file: Option<std::path::PathBuf>,
) -> Result<(), AppError> {
    let fingerprint = if vox_core::node::profile::Profile::exists(paths) {
        let attached = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()
            .and_then(|rt| {
                rt.block_on(async {
                    let at = crate::client::one_shot(paths).ok()?;
                    IpcClient::open_at(&at).await.ok()?.me()
                })
            });
        match attached {
            Some(me) => me,
            // Not attached: the node's files say it, in the clear (a fingerprint is public).
            None => vox_core::node::profile::Profile::open(paths.clone())?.fingerprint(),
        }
    } else {
        // **A node with no identity has one made here** (ADR-026 C-5), with a passphrase asked
        // twice at a terminal or given, never by a daemon.
        let passphrase = zeroize::Zeroizing::new(crate::tunnel_cli::identity_passphrase_for(
            paths, flag, file,
        )?);
        let made = crate::client::create_identity(paths, &passphrase)?;
        // On stderr: stdout is the fingerprint alone, for a pipe.
        eprintln!("vox: {}", crate::ident::NO_BACKUP);
        made
    };
    // The whole fingerprint, alone on the line, so it pipes and pastes without editing.
    println!("{}", vox_core::node::link::b32_encode(&fingerprint));
    Ok(())
}

/// `vox room leave` — leave a room (V210-164; the decider, 2026-10-03: "leave deletes it").
///
/// The node writes its departure into the room and answers once another member has it; then
/// the room is gone from this node, and so are the read cursors agent sessions kept for it here
/// (the node deletes those with the room).
/// The other members stop listing this identity in the room's roster. Joining again later is an
/// ordinary join.
///
/// # Errors
/// If the node cannot be reached, the room is unknown or closed, or no other member could be
/// told in time (the node then leaves as soon as one can be).
pub async fn leave(paths: &Paths, room: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    let name = rooms_of(&mut client)
        .await?
        .into_iter()
        .find(|(id, _, _, _)| *id == channel_id)
        .map(|(_, name, _, _)| name)
        .unwrap_or_default();
    let which = if name.is_empty() {
        format!("room {}", b32_encode(&channel_id))
    } else {
        format!("room {name:?} ({})", b32_encode(&channel_id))
    };
    match client.request(&Request::Leave { channel_id }).await {
        Ok(Frame::Ok) => {
            println!("vox: left {which}");
            println!("     its other members see that you left; this node no longer holds it");
            Ok(())
        }
        Ok(Frame::Error { reason }) => {
            Err(AppError::Usage(format!("{which} was not left: {reason}")))
        }
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room end` — end a room for everyone; its creator only (V030-08).
///
/// # Errors
/// An unreachable node, an unknown or closed room, an ended room, or a caller who did not
/// create it.
pub async fn end(paths: &Paths, room: &str) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    match client.request(&Request::End { channel_id }).await {
        Ok(Frame::Ok) => {
            println!("vox: ended {} for everyone", short(&channel_id));
            println!(
                "     every member's node takes no new message in it once it has this, passes the end \
                 on, and deletes the room"
            );
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(format!("cannot end: {reason}"))),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// `vox room admin add|remove|list` — a room's admins (V030-08).
///
/// # Errors
/// An unknown action, an unreachable node, an unknown or closed room, an unknown member, a
/// caller who did not create the room, or a member who is not an admin (`remove`).
pub async fn admin(
    paths: &Paths,
    action: &str,
    room: &str,
    member: Option<&str>,
) -> Result<(), AppError> {
    let mut client = attach(paths).await?;
    let channel_id = room_of(&mut client, room).await?;
    if action == "list" {
        return match client.request(&Request::Admins { channel_id }).await {
            Ok(Frame::Members { members }) => {
                for (i, m) in members.iter().enumerate() {
                    println!("{}{}", id(m), if i == 0 { "  (creator)" } else { "" });
                }
                Ok(())
            }
            Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
            Ok(other) => Err(crate::client::unexpected(&other)),
            Err(e) => Err(AppError::Usage(e.to_string())),
        };
    }
    let add = match action {
        "add" => true,
        "remove" => false,
        other => {
            return Err(AppError::Usage(format!(
                "{other:?} is not an admin action: use add, remove or list"
            )))
        }
    };
    let Some(member) = member else {
        return Err(AppError::Usage(format!(
            "`vox room admin {action}` needs the member's fingerprint (`vox room roster` lists them)"
        )));
    };
    let members = match client.request(&Request::Roster { channel_id }).await {
        Ok(Frame::Members { members }) => members,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let member = resolve_prefix(member, &members)?;
    match client
        .request(&Request::SetAdmin {
            channel_id,
            member,
            admin: add,
        })
        .await
    {
        Ok(Frame::Ok) => {
            println!(
                "vox: {} is {} admin of {}",
                short(&member),
                if add { "now an" } else { "no longer an" },
                short(&channel_id)
            );
            Ok(())
        }
        Ok(Frame::Error { reason }) => Err(AppError::Usage(format!(
            "cannot {action} the admin: {reason}"
        ))),
        Ok(other) => Err(crate::client::unexpected(&other)),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}
