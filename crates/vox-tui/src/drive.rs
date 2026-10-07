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

/// Why a drive did not reach its session, in the three ways every surface words alike (CL-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotDelivered {
    /// The session's node refused it: "not delivered to <label>: <why>".
    Refused(String),
    /// Nothing went out: the node could not be reached, or no single target was found (DR-5):
    /// "not sent to <label>: <why>".
    NotSent(String),
    /// It went out and no answer came: "no answer from <label>: it may or may not have been
    /// delivered".
    NoAnswer(String),
}

impl NotDelivered {
    /// The sentence a person reads, for the Session labelled `label`.
    #[must_use]
    pub fn sentence(&self, label: &str) -> String {
        match self {
            NotDelivered::Refused(why) => format!("not delivered to {label}: {why}"),
            NotDelivered::NotSent(why) => format!("not sent to {label}: {why}"),
            NotDelivered::NoAnswer(_) => {
                format!("no answer from {label}: it may or may not have been delivered")
            }
        }
    }
}

/// Drive `session` of the node `peer` in `room`, from the node at `paths` (the CLI's and the
/// TUI's side). What happened, in words.
///
/// # Errors
/// [`NotDelivered`]: refused by the session's node, not sent, or not answered.
pub async fn send(
    paths: &vox_core::node::paths::Paths,
    room: vox_core::hash::Digest32,
    peer: vox_core::hash::Digest32,
    request: &Request,
) -> Result<String, NotDelivered> {
    use vox_core::node::drive_input::Unsent;
    let at = crate::client::one_shot(paths).map_err(|e| NotDelivered::NotSent(e.to_string()))?;
    match vox_core::node::drive_input::send(&at, room, peer, request).await {
        Ok(Answer { ok: true, said }) => Ok(said),
        Ok(Answer { ok: false, said }) => Err(NotDelivered::Refused(said)),
        Err(Unsent::Unreachable(why)) => Err(NotDelivered::NotSent(why)),
        Err(Unsent::NoAnswer(why)) => Err(NotDelivered::NoAnswer(why)),
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
    let (channel_id, node, id, label) = target(paths, room, session).await?;
    deliver(paths, channel_id, node, id, &label, action).await
}

/// `vox room session ROOM SESSION --file PATH [--note TEXT]`: send the session a file (ADR-029
/// DR-1.7, #546). This node serves it as a share only the session's node may fetch, once, then
/// says so on the drive request; the session's node answers that it is pulling it, and says in
/// the Session where it landed, or why not.
///
/// # Errors
/// As [`run`]; and a file that cannot be read or served is not sent.
pub async fn run_file(
    paths: &vox_core::node::paths::Paths,
    room: &str,
    session: &str,
    path: &std::path::Path,
    note: Option<&str>,
) -> Result<(), crate::app::AppError> {
    use crate::app::AppError;
    let (channel_id, node, id, label) = target(paths, room, session).await?;
    match send_file(paths, channel_id, node, id, path, note).await {
        Ok(said) => {
            use std::io::Write as _;
            let _ = writeln!(std::io::stdout().lock(), "{label}: {said}");
            Ok(())
        }
        Err(not) => Err(AppError::Usage(not.sentence(&label))),
    }
}

/// Send Session `session_id` of `node` in room `channel_id` a file (ADR-029 DR-1.7, #546), as
/// `vox room session --file` and the TUI's `:share` do: serve `path` as a share only `node` may
/// fetch, once, then say so on the drive request. What the session's node answered ("accepted,
/// pulling n bytes"); or why not, in the words every drive uses (CL-1). A file not taken is not
/// served on.
///
/// # Errors
/// [`NotDelivered`]: the file could not be read or served (not sent), the session's node refused
/// it, or no answer came.
pub async fn send_file(
    paths: &vox_core::node::paths::Paths,
    channel_id: vox_core::hash::Digest32,
    node: vox_core::hash::Digest32,
    session_id: String,
    path: &std::path::Path,
    note: Option<&str>,
) -> Result<String, NotDelivered> {
    use vox_core::node::ipc::{Request as Ipc, SessionTo};
    let path = std::fs::canonicalize(path)
        .map_err(|e| NotDelivered::NotSent(format!("{}: {e}", path.display())))?;
    let note = note.map(str::trim).filter(|n| !n.is_empty());
    let mut env =
        vox_agentcomms::envelope::Envelope::new(crate::room_cli::FILE, note.unwrap_or(""));
    if let Some(n) = note {
        env.data = serde_json::json!({ "note": n });
    }
    let mut client = crate::room_cli::attach(paths)
        .await
        .map_err(|e| NotDelivered::NotSent(e.to_string()))?;
    let row = crate::share_cli::shares_of(
        client
            .request(&Ipc::SessionShare {
                channel_id,
                path: path.to_string_lossy().into_owned(),
                envelope: env.to_text(),
                to: SessionTo::Node(node),
            })
            .await,
    )
    .map_err(|e| NotDelivered::NotSent(e.to_string()))?
    .into_iter()
    .next()
    .ok_or_else(|| NotDelivered::NotSent("the daemon did not serve it".into()))?;
    let tag = row.tag.clone();
    let request = Request {
        v: 1,
        session: session_id,
        action: Action::File {
            name: row.name,
            size: row.size,
            sha256: row.sha256,
            tag: row.tag,
            note: note.map(str::to_owned),
        },
    };
    let sent = send(paths, channel_id, node, &request).await;
    // Not taken: served to no one, so not served at all.
    if sent.is_err() {
        let _ = client
            .request(&Ipc::ShareStop {
                channel_id,
                selector: tag,
            })
            .await;
    }
    sent
}

/// The one open Session `session` names in `room`: its room, its node, its id and its label;
/// refused before anything is sent when it names none, several, an ended one, or one of a node
/// this node does not trust.
async fn target(
    paths: &vox_core::node::paths::Paths,
    room: &str,
    session: &str,
) -> Result<
    (
        vox_core::hash::Digest32,
        vox_core::hash::Digest32,
        String,
        String,
    ),
    crate::app::AppError,
> {
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
    Ok((channel_id, row.node, row.id.clone(), label))
}

/// Send `action` to Session `id` of `node`, and say what came of it.
async fn deliver(
    paths: &vox_core::node::paths::Paths,
    channel_id: vox_core::hash::Digest32,
    node: vox_core::hash::Digest32,
    id: String,
    label: &str,
    action: Action,
) -> Result<(), crate::app::AppError> {
    use crate::app::AppError;
    // Whether this node may drive it is the session's node's to say, from its own keyring
    // (DR-2): it is asked, never assumed.
    let request = Request {
        v: 1,
        session: id,
        action,
    };
    match send(paths, channel_id, node, &request).await {
        Ok(said) => {
            use std::io::Write as _;
            let _ = writeln!(std::io::stdout().lock(), "{label}: {said}");
            Ok(())
        }
        Err(not) => Err(AppError::Usage(not.sentence(label))),
    }
}
