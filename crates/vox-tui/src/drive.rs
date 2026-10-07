//! ADR-029 §3 — **driving a Session**: a member with drive types into a session, interrupts or
//! stops it, sends it a slash command, or answers its approval or question; the input reaches
//! exactly that session, or is refused with the reason, every time (DR-1, DR-2, DR-5, DR-6, DR-7;
//! #544).
//!
//! **The path.** The driver's node opens an app stream (ADR-022 decision 7) to the session's node,
//! in the Session's room, speaking [`LABEL`]: one request line, one answer line (the lead,
//! 2026-10-06: no new wire kind). The app gate admits only a member of the room in each node's
//! keyring, both ways. A driver must therefore trust the session's node; a member with drive
//! does already, since it reads the Session only through that node's drive key, which it accepts
//! only from a node it trusts (#543). The gate works over a mutually
//! authenticated, encrypted connection, so the session's node knows who drives without a seal of
//! its own; nothing is queued, so input never arrives late, and an unreachable node is said at
//! once.
//!
//! **What the session's node checks**, in this order, refusing with the reason at the first that
//! fails ([`Router::drive`](crate::host::Router)): that its keyring trusts the driver with drive
//! (DR-2); that the session is registered here and has not ended (TA-5); that it works in the room
//! the stream was opened in. Then it hands the input to that session's harness and to nothing
//! else: Claude Code through its tmux pane, Codex through its app-server, OpenCode through Vox's
//! plugin; an answer through the request's waiter ([`crate::session_sink::Sink::answer`]). There
//! is no fallback to another session of the node, ever (DR-5).
//!
//! **What the Session shows.** The session's node writes what was driven (`drive`, with `by`, the
//! driver's whole fingerprint, as the node's claim) and, when it was not delivered, why
//! (`drive-result`), so every member with drive reads who drove what and what came of it.

pub use vox_agentcomms::drive::{slash, Action, Answer, Request, LABEL, MAX_REQUEST, PATIENCE};

/// Drive `session` of the node `peer` in `room`, from the node at `paths` (the CLI's side).
///
/// # Errors
/// Why it was not delivered: refused by the session's node, or that node could not be reached.
pub async fn send(
    paths: &vox_core::node::paths::Paths,
    room: vox_core::hash::Digest32,
    peer: vox_core::hash::Digest32,
    request: &Request,
) -> Result<String, String> {
    let at = crate::client::one_shot(paths).map_err(|e| e.to_string())?;
    match vox_core::node::drive_input::send(&at, room, peer, request).await {
        Ok(Answer { ok: true, said }) => Ok(said),
        Ok(Answer { ok: false, said }) => Err(said),
        Err(unsent) => Err(unsent.to_string()),
    }
}

/// `vox room session ROOM SESSION --say … | --interrupt | --stop | --slash … | --approve … |
/// --reject … | --answer …`: drive one open Session, and say what came of it. A refusal is said
/// with its reason and exits non-zero (DR-6).
///
/// # Errors
/// If the node cannot be reached, the room or the Session cannot be named, or the input was not
/// delivered.
pub async fn run(
    paths: &vox_core::node::paths::Paths,
    room: &str,
    session: &str,
    action: Action,
) -> Result<(), crate::app::AppError> {
    use crate::app::AppError;
    use vox_core::node::ipc::{Frame, Request as Ipc};
    let mut client = crate::room_cli::attach(paths).await?;
    let channel_id = crate::room_cli::room_of(&mut client, room).await?;
    let sessions = match client.request(&Ipc::Sessions { channel_id }).await {
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
    // Exactly one open Session, never a guess (DR-5); an ended one is refused (TA-5).
    let row = vox_core::node::sessions::resolve(&sessions, session, false, label_of)
        .map_err(AppError::Usage)?;
    let label = label_of(row);
    // The app gate opens a stream only between nodes that trust each other. That costs a member
    // with drive nothing: it reads a Session only through the session node's drive key, which it
    // takes only from a node it trusts (#543), so a driver already trusts the session's node.
    // Said here, before anything is sent, rather than as an unreachable peer.
    let trusted = match client.trusted("").await {
        Ok(Frame::Trusted { entries }) => entries.iter().any(|(fp, _, _)| *fp == row.node),
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    if !trusted {
        let node = crate::ident::name_of(&row.node);
        return Err(AppError::Usage(format!(
            "not sent to {label}: you do not trust {node}, so you cannot drive or read its \
             Sessions"
        )));
    }
    // Whether this node may drive it is the session's node's to say, from its own keyring
    // (DR-2): it is asked, never assumed.
    drop(client);
    let request = Request {
        v: 1,
        session: row.id.clone(),
        action,
    };
    match send(paths, channel_id, row.node, &request).await {
        Ok(said) => {
            use std::io::Write as _;
            let _ = writeln!(std::io::stdout().lock(), "{label}: {said}");
            Ok(())
        }
        Err(why) => Err(AppError::Usage(format!("not delivered to {label}: {why}"))),
    }
}
