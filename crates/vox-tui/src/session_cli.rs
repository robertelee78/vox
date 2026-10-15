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
    let (rows, older, instance) = match client.session_page(channel_id, which, before).await {
        Ok(Frame::SessionPage {
            rows,
            older,
            instance,
        }) => (rows, older, instance),
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let first = rows
        .first()
        .map(|r| vox_core::node::link::b32_encode(&r.entry_hash));
    if raw {
        if let (Some(first), true) = (&first, older > 0) {
            eprintln!("{older} older raw records not shown: vox room session {} {} --raw{} --before {first}",
                room.trim(), named, if json { " --json" } else { "" });
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
        eprintln!(
            "{older} older {} not shown: vox room session {} {} --before {first}",
            if older == 1 { "entry" } else { "entries" },
            room.trim(),
            read.id
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
            let answer_with = format!("vox room session {} {}", room.trim(), read.id);
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
