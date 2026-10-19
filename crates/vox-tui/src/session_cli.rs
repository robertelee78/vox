//! `vox room session ROOM <session>` — **one Session, read the way a member with drive reads it**
//! (ADR-029 SC-1, CL-1; #540, #545).
//!
//! What each line says is [`vox_core::node::session_view`]'s, shared with the TUI and the app; this
//! prints it. `--details` adds each entry's full input and output under its line, a split entry
//! joined whole.

use serde_json::Value;
use vox_core::hash::Digest32;
use vox_core::node::session_view::render;
// The TUI reads a Session through these, as this verb does (CL-1).
pub use vox_core::node::session_view::{lines, of_session, waiting, Line, Names, Waiting};

/// One Session's lines, each with its Details as plain lines, named as this node names its members:
/// what `vox room session --details` prints, for the TUI to draw the same words (CL-1). `rows` are
/// the Session's entries, in order; `label` its label.
#[must_use]
pub fn drawn(
    rows: &[vox_core::node::drive::SessionRow],
    label: &str,
) -> Vec<(String, Vec<String>)> {
    lines(rows, label, &ByIdent)
        .into_iter()
        .map(|l| {
            let details = crate::session_drive_ui::details(&l.details);
            (l.text, details)
        })
        .collect()
}

/// How this command names nodes: the names this node gave them ([`crate::ident`]).
struct ByIdent;

impl Names for ByIdent {
    fn alias(&self, fp: &Digest32) -> String {
        crate::ident::name_of(fp)
    }
    fn is_me(&self, by: &str) -> bool {
        vox_core::node::link::b32_decode(by, "fingerprint")
            .is_ok_and(|fp| crate::ident::name_of(&fp) == crate::ident::YOU)
    }
    fn alias_b32(&self, by: &str) -> String {
        match vox_core::node::link::b32_decode(by, "fingerprint") {
            Ok(fp) => crate::ident::name_of(&fp),
            Err(_) => by.chars().take(12).collect(),
        }
    }
}

/// `vox room session ROOM SESSION [--details | --raw] [--json] [--before ENTRY]`: one page of the
/// Session, the newest or the one before ENTRY, and under it how to print the page before it
/// (ADR-034 FR-4): never the whole history.
///
/// # Errors
/// If the node cannot be reached, the room is unknown or closed, or no one Session answers to
/// `session`.
pub async fn show(
    paths: &vox_core::node::paths::Paths,
    room: &str,
    session: &str,
    details: bool,
    json: bool,
    raw: bool,
    before: Option<&str>,
) -> Result<(), crate::app::AppError> {
    use crate::app::AppError;
    use vox_core::node::ipc::Frame;
    let mut client = crate::room_cli::attach(paths).await?;
    let channel_id = crate::room_cli::room_of(&mut client, room).await?;
    let room_id = vox_core::node::link::b32_encode(&channel_id);
    let acting_node = crate::client::name_of(paths)?;
    let actor = client
        .me()
        .ok_or_else(|| AppError::Usage("the selected node is locked".into()))?;
    let label_of = |s: &vox_core::node::sessions::SessionRow| {
        vox_agentcomms::envelope::session_label(
            &crate::ident::name_of(&s.node),
            s.name.as_deref(),
            &s.id,
        )
    };
    // The Session the room's Sessions name; else the daemon looks among its entries for the one
    // `session` names, whose opening has not arrived yet.
    let selected = vox_core::node::sessions::selection::lookup(
        &mut client,
        channel_id,
        None,
        session,
        true,
        label_of,
    )
    .await
    .map_err(AppError::Usage)?;
    let named = selected
        .as_ref()
        .map_or_else(|| session.trim().to_owned(), |s| s.id.clone());
    let sessions: Vec<_> = selected.into_iter().collect();
    let before = before
        .map(|b| vox_core::node::link::b32_decode(b.trim(), "entry"))
        .transpose()
        .map_err(|_| AppError::Usage(format!("--before {}: not an entry", before.unwrap_or(""))))?;
    let which = if raw {
        vox_core::node::drive::SessionFilter::SessionRaw(named.clone())
    } else {
        vox_core::node::drive::SessionFilter::Session(named.clone())
    };
    let (mut rows, mut older, instance) =
        match client.session_page(channel_id, which.clone(), before).await {
            Ok(Frame::SessionPage {
                rows,
                older,
                instance,
            }) => (rows, older, instance),
            Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
            Ok(other) => return Err(crate::client::unexpected(&other)),
            Err(e) => return Err(AppError::Usage(e.to_string())),
        };
    // One read shows the whole current turn (ADR-029 CL-2). A page is bounded by the IPC
    // frame, so a turn with one large tool output ran past it and the prompt and the call that
    // made the output fell off the page a person reads first ("2 older entries not shown").
    // The older pages are followed until the turn's prompt is in hand or the Session's start,
    // a bounded number of pages back; an explicit --before pages by hand, as before.
    if before.is_none() && !raw {
        const TURN_PAGES: usize = 8;
        let has_prompt = |rows: &[_]| {
            rows.iter().any(|r: &vox_core::node::drive::SessionRow| {
                serde_json::from_str::<Value>(&r.body)
                    .is_ok_and(|v| v.get("kind").and_then(Value::as_str) == Some("user"))
            })
        };
        let mut followed = 0;
        while older > 0 && followed < TURN_PAGES && !has_prompt(&rows) {
            let Some(first) = rows.first().map(|r| r.entry_hash) else {
                break;
            };
            match client
                .session_page(channel_id, which.clone(), Some(first))
                .await
            {
                Ok(Frame::SessionPage {
                    rows: earlier,
                    older: left,
                    instance: same,
                }) => {
                    if earlier.is_empty() || same != instance {
                        break;
                    }
                    older = left;
                    let mut all = earlier;
                    all.extend(rows);
                    rows = all;
                }
                Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
                Ok(other) => return Err(crate::client::unexpected(&other)),
                Err(e) => return Err(AppError::Usage(e.to_string())),
            }
            followed += 1;
        }
    }
    let first = rows
        .first()
        .map(|r| vox_core::node::link::b32_encode(&r.entry_hash));
    if raw {
        if let (Some(first), true) = (&first, older > 0) {
            let mut words = vec![
                "vox", "room", "session", &room_id, &named, "--raw", "--before", first,
            ];
            if json {
                words.push("--json");
            }
            eprintln!(
                "{older} older raw records not shown: {}",
                vox_text::shell::node_command(&words, acting_node.as_str())
            );
        }
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        for row in rows {
            let entry = vox_core::node::link::b32_encode(&row.entry_hash);
            let author = vox_core::node::link::b32_encode(&row.author);
            if json {
                writeln!(
                    out,
                    "{}",
                    serde_json::json!({
                        "entry": entry, "author": author, "created_millis": row.created_millis,
                        "session": row.session_id, "body": row.body,
                    })
                )
                .map_err(|e| AppError::Usage(e.to_string()))?;
            } else {
                writeln!(out, "{entry} {author} {}\n{}", row.created_millis, row.body)
                    .map_err(|e| AppError::Usage(e.to_string()))?;
            }
        }
        return Ok(());
    }
    let read =
        vox_core::node::session_view::read(&sessions, rows, session, None, &label_of, &ByIdent)
            .map_err(AppError::Usage)?;
    // What is not shown, and how to show it, on stderr: stdout stays the page.
    if let (Some(first), true) = (&first, older > 0 && read.hidden.is_none()) {
        let mut words = vec![
            "vox", "room", "session", &room_id, &read.id, "--before", first,
        ];
        if details {
            words.push("--details");
        }
        if json {
            words.push("--json");
        }
        eprintln!(
            "{older} older {} not shown: {}",
            if older == 1 { "entry" } else { "entries" },
            vox_text::shell::node_command(&words, acting_node.as_str())
        );
    }
    use std::io::Write as _;
    {
        let mut out = std::io::stdout().lock();
        if let Some(hidden) = &read.hidden {
            let _ = writeln!(out, "{} · {}", read.label, read.state);
            let _ = writeln!(out, "{hidden}");
            return Ok(());
        }
        if json {
            for l in &read.lines {
                let d: serde_json::Map<String, Value> = l
                    .details
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect();
                let _ = writeln!(
                    out,
                    "{}",
                    serde_json::json!({
                        "seq": l.seq, "kind": l.kind, "line": l.text, "ref": l.reference,
                        "waiting": l.waiting.is_some(),
                        "details": if details { Value::Object(d) } else { Value::Null },
                    })
                );
            }
        } else {
            let _ = writeln!(out, "{} · {}", read.label, read.state);
            let answer_with = vox_text::shell::node_command(
                &["vox", "room", "session", &room_id, &read.id],
                acting_node.as_str(),
            );
            let _ = write!(out, "{}", render(&read.lines, details, &answer_with));
        }
        // A live owner may be unreachable. Deliver locally readable history before that wait,
        // including when stdout is a pipe. Do not retain the stdout lock across network I/O.
        out.flush().map_err(|e| AppError::Usage(e.to_string()))?;
    }
    // This is the owner's durable room state, not a flag inferred from the saved transcript.
    // A disconnected owner does not prevent reading history, and never implies Resume.
    let pause = if read.hidden.is_none() {
        let at = crate::client::one_shot(paths)?;
        Some(
            vox_core::node::room_pause::status_checked(&at, channel_id, read.node, actor, instance)
                .await,
        )
    } else {
        None
    };
    // Preserve NDJSON activity records; status is metadata on stderr in --json mode.
    let pause_words = match pause {
        Some(Ok(state)) if state.paused => {
            let when = if state.at_millis < 253_402_300_800_000 {
                crate::room_cli::millis_as_time(state.at_millis)
            } else {
                format!("{} ms since Unix epoch", state.at_millis)
            };
            Some(format!(
                "Paused by {} at {when}",
                crate::ident::name_of(&state.by)
            ))
        }
        Some(Err(why)) => Some(format!("Pause status unknown: {why}")),
        _ => None,
    };
    if let Some(pause) = pause_words {
        if json {
            eprintln!("{pause}");
        } else {
            let mut out = std::io::stdout().lock();
            writeln!(out, "{pause}").map_err(|e| AppError::Usage(e.to_string()))?;
            out.flush().map_err(|e| AppError::Usage(e.to_string()))?;
        }
    }
    Ok(())
}

/// Exact private selection; a page can never be carried to another room incarnation or opening.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct AttentionSelection {
    pub actor: Digest32,
    pub room: Digest32,
    pub owner: Digest32,
    pub session: String,
    pub opening: Digest32,
    pub instance: [u8; 16],
}

/// Read current authorization and incarnation through local IPC, without fetching activity.
pub(crate) async fn attention_context(
    client: &mut vox_core::node::ipc::IpcClient,
    room: Digest32,
    owner: Digest32,
    session: &str,
) -> Result<AttentionSelection, String> {
    use vox_core::node::ipc::{Frame, Request};
    let actor = client.me().ok_or("the selected node is not Ready")?;
    let instance = match client
        .request(&Request::ArrivalHead { channel_id: room })
        .await
    {
        Ok(Frame::ArrivalHead { head }) => head.instance,
        Ok(Frame::Error { reason }) => return Err(reason),
        Err(e) => return Err(format!("cannot read the saved room: {e}")),
        _ => return Err("the daemon did not answer the saved room selection".into()),
    };
    let opening = match client.session_lookup(room, owner, session.to_owned()).await {
        Ok(Frame::SessionsPage {
            sessions,
            summaries,
            more: false,
            ..
        }) if sessions.len() == 1 && summaries.len() == 1 => {
            let row = &sessions[0];
            if row.node != owner || row.id != session || !row.can_drive || !row.open {
                return Err("the selected open Session is no longer readable with drive".into());
            }
            row.opening
        }
        Ok(Frame::Error { reason }) => return Err(reason),
        _ => return Err("the selected open Session is no longer readable with drive".into()),
    };
    match client
        .request(&Request::ArrivalHead { channel_id: room })
        .await
    {
        Ok(Frame::ArrivalHead { head }) if head.instance == instance => {}
        Ok(Frame::Error { reason }) => return Err(reason),
        _ => return Err("the saved room changed while selecting attention".into()),
    }
    Ok(AttentionSelection {
        actor,
        room,
        owner,
        session: session.to_owned(),
        opening,
        instance,
    })
}

/// An independent, cancellable read. Dropping this future closes its private IPC connections.
/// Local drive permission and exact selection are checked on both sides of the remote query.
pub(crate) async fn attention_page(
    at: &vox_core::node::ipc::NodeSocket,
    selected: &AttentionSelection,
    after: Option<vox_core::node::attention::Cursor>,
) -> Result<vox_core::node::attention::Page, String> {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut client = vox_core::node::ipc::IpcClient::open_at(at)
            .await
            .map_err(|e| e.to_string())?;
        if attention_context(
            &mut client,
            selected.room,
            selected.owner,
            &selected.session,
        )
        .await?
            != *selected
        {
            return Err("the selected Session changed before reading attention".into());
        }
        let page = vox_core::node::attention::page_checked(
            at,
            selected.room,
            selected.owner,
            &selected.session,
            selected.opening,
            selected.actor,
            selected.instance,
            after,
        )
        .await?;
        if attention_context(
            &mut client,
            selected.room,
            selected.owner,
            &selected.session,
        )
        .await?
            != *selected
        {
            return Err("the selected Session changed while reading attention".into());
        }
        Ok(page)
    })
    .await
    .map_err(|_| "attention query timed out; current state is unknown".to_owned())?
}

/// Shared CLI/TUI wording: transport acceptance is never a promise of an answer.
#[must_use]
pub(crate) fn attention_words(row: &vox_core::node::attention::Row) -> &'static str {
    use vox_core::node::attention::{State, Wait};
    match (row.state, row.wait) {
        (State::Queued, Some(Wait::NextCodexTurn)) => "Waiting for next Codex turn",
        (State::Queued, Some(Wait::Paused)) => "Queued — room paused",
        (State::Queued, Some(Wait::NextTurnAfterResume)) => {
            "Queued — waiting for the next turn after resume"
        }
        (State::Queued, Some(Wait::AdapterUnavailable)) => "Queued — input adapter unavailable",
        (State::Queued, Some(Wait::Unknown)) => {
            "Queued — notice acceptance unknown; awaiting a receipt"
        }
        (State::Queued, None) => "Queued — awaiting delivery",
        (State::Delivered, _) => "Delivered to harness — running turn not observed",
        (State::Answering, _) => "Answering — running turn observed",
        (State::Answered, _) => "Answered",
        (State::Unavailable, _) => "Unavailable",
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AttentionContinuation {
    selection: AttentionSelection,
    after: vox_core::node::attention::Cursor,
}

/// One explicitly requested private attention page. Activity NDJSON is a separate mode.
///
/// # Errors
/// Refuses unreadable/ended selections, stale cursors and an unavailable current observation.
pub async fn show_attention(
    paths: &vox_core::node::paths::Paths,
    room: &str,
    session: &str,
    json: bool,
    after: Option<&str>,
) -> Result<(), crate::app::AppError> {
    use crate::app::AppError;
    use vox_core::node::link::b32_encode;
    let mut client = crate::room_cli::attach(paths).await?;
    let room = crate::room_cli::room_of(&mut client, room).await?;
    let row =
        vox_core::node::sessions::selection::resolve(&mut client, room, None, session, true, |s| {
            vox_agentcomms::envelope::session_label(
                &crate::ident::name_of(&s.node),
                s.name.as_deref(),
                &s.id,
            )
        })
        .await
        .map_err(AppError::Usage)?;
    let selected = attention_context(&mut client, room, row.node, &row.id)
        .await
        .map_err(AppError::Usage)?;
    if selected.opening != row.opening {
        return Err(AppError::Usage(
            "the selected Session reopened; select it again before reading attention".into(),
        ));
    }
    let after = after.map(|raw| {
        if raw.len() > 4096 { return Err(AppError::Usage("attention continuation is too long".into())); }
        let cursor: AttentionContinuation = serde_json::from_str(raw)
            .map_err(|_| AppError::Usage("invalid attention continuation; refresh the first page".into()))?;
        if cursor.selection != selected {
            return Err(AppError::Usage("attention continuation belongs to a different selection; refresh the first page".into()));
        }
        Ok(cursor.after)
    }).transpose()?;
    let at = crate::client::one_shot(paths)?;
    let page = attention_page(&at, &selected, after)
        .await
        .map_err(AppError::Usage)?;
    let next = page
        .next
        .map(|after| {
            serde_json::to_string(&AttentionContinuation {
                selection: selected.clone(),
                after,
            })
        })
        .transpose()
        .map_err(|e| AppError::Usage(e.to_string()))?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema": "vox-session-attention/v1", "room": b32_encode(&room),
                "node": b32_encode(&row.node), "session": row.id, "opening": b32_encode(&row.opening),
                "revision": page.revision, "preparing": page.preparing,
                "rows": page.rows.iter().map(|r| serde_json::json!({
                    "source": b32_encode(&r.source), "state": r.state, "wait": r.wait,
                    "observed_at_ms": r.at_millis, "answer": r.answer.map(|a| b32_encode(&a)),
                    "reason": r.reason, "line": attention_words(r),
                })).collect::<Vec<_>>(), "next": next,
            })
        );
    } else {
        println!(
            "Private room attention · {} · {}",
            crate::ident::name_of(&row.node),
            row.id
        );
        if page.preparing {
            println!("Thread audience is still being checked");
        } else if page.rows.is_empty() {
            println!("No observations on this page.");
        }
        for r in &page.rows {
            println!(
                "{} · {} · observed {} ms since Unix epoch",
                b32_encode(&r.source),
                attention_words(r),
                r.at_millis
            );
            if let Some(answer) = r.answer {
                println!("  answer: {}", b32_encode(&answer));
            }
            if let Some(reason) = &r.reason {
                println!(
                    "  {}",
                    vox_text::shown(reason, vox_core::node::attention::MAX_BYTES)
                );
            }
        }
        println!("Delivery does not promise a reply. This is one private page, not a room-wide response count.");
    }
    if let Some(next) = next {
        let room = b32_encode(&room);
        let mut words = vec![
            "vox",
            "room",
            "session",
            &room,
            &row.id,
            "--attention",
            "--attention-after",
            &next,
        ];
        if json {
            words.push("--json");
        }
        eprintln!(
            "Next attention page: {}",
            vox_text::shell::node_command(&words, crate::client::name_of(paths)?.as_str())
        );
    }
    Ok(())
}
