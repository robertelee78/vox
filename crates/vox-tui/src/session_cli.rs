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

/// `vox room session ROOM SESSION [--details] [--json]`.
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
) -> Result<(), crate::app::AppError> {
    use crate::app::AppError;
    use vox_core::node::ipc::{Frame, Request};
    let mut client = crate::room_cli::attach(paths).await?;
    let channel_id = crate::room_cli::room_of(&mut client, room).await?;
    let sessions = match client.request(&Request::Sessions { channel_id }).await {
        Ok(Frame::Sessions { sessions }) => sessions,
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
    let rows = match client
        .request(&Request::SessionEntries { channel_id })
        .await
    {
        Ok(Frame::SessionEntries { rows }) => rows,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let read =
        vox_core::node::session_view::read(&sessions, rows, session, None, &label_of, &ByIdent)
            .map_err(AppError::Usage)?;
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
