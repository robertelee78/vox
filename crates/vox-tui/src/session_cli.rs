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

/// `vox room session ROOM SESSION [--details] [--json] [--before ENTRY]`: one page of the
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
    before: Option<&str>,
) -> Result<(), crate::app::AppError> {
    use crate::app::AppError;
    use vox_core::node::ipc::Frame;
    let mut client = crate::room_cli::attach(paths).await?;
    let channel_id = crate::room_cli::room_of(&mut client, room).await?;
    let sessions = match client.sessions(channel_id).await {
        Ok(Frame::SessionsPage { sessions, .. }) => sessions,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let label_of = |s: &vox_core::node::sessions::SessionRow| {
        vox_agentcomms::envelope::session_label(
            &crate::ident::name_of(&s.node),
            s.name.as_deref(),
            &s.id,
        )
    };
    // The Session the room's Sessions name; else the daemon looks among its entries for the one
    // `session` names, whose opening has not arrived yet.
    let named = vox_core::node::sessions::resolve(&sessions, session, true, label_of)
        .map_or_else(|_| session.trim().to_owned(), |s| s.id.clone());
    let before = before
        .map(|b| vox_core::node::link::b32_decode(b.trim(), "entry"))
        .transpose()
        .map_err(|_| AppError::Usage(format!("--before {}: not an entry", before.unwrap_or(""))))?;
    let which = vox_core::node::drive::SessionFilter::Session(named);
    let (rows, older) = match client.session_page(channel_id, which, before).await {
        Ok(Frame::SessionPage { rows, older }) => (rows, older),
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let first = rows
        .first()
        .map(|r| vox_core::node::link::b32_encode(&r.entry_hash));
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
    Ok(())
}
