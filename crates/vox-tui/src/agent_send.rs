//! `vox agent send <path> [--note TEXT]`: **send a file out of this session's Session** (ADR-029
//! DR-1.8, #546).
//!
//! Run from the session, it names the session the way every agent verb does (`--session`,
//! `VOX_SESSION`, then the harness's own id) and its node the way the session's hook does
//! (`--node`, else `VOX_NODE`), and sends to the room the session works in. The daemon hashes and
//! serves the file or folder as `vox share` does, but posts nothing to the room: the share is
//! announced as the Session's `file` entry, sealed under the node's drive key, so only the members
//! the node trusts with drive learn of it, and only they are served it. Their nodes pull it by
//! themselves. It never attaches the node and asks for no passphrase.

use crate::room_cli::FILE;
use vox_agentcomms::envelope::Envelope;
use vox_core::node::ipc::{Request, SessionTo};
use vox_core::node::paths::{Account, NodeName};

use crate::app::AppError;

/// `vox agent send`.
///
/// # Errors
/// No node or session named, a session that works in no room, a path that cannot be read, a node
/// not attached, or the daemon's refusal.
pub async fn run(
    account: &Account,
    node: &NodeName,
    session_flag: Option<&str>,
    path: &std::path::Path,
    note: Option<&str>,
) -> Result<(), AppError> {
    let session = crate::coord::require_session(session_flag)?;
    let paths = account.node_paths(node)?;
    let label: String = session.chars().take(8).collect();
    let room = crate::wake::registration(&paths, &session)
        .and_then(|r| r.room)
        .ok_or_else(|| {
            AppError::Usage(format!(
                "session {label} of node {node} works in no room, so its Session has nowhere to \
                 send a file: vox agent room and a room's id sets it (vox room list shows them)"
            ))
        })?;
    let channel_id = vox_core::node::link::b32_decode(&room, "the session's room")
        .map_err(|e| AppError::Usage(e.to_string()))?;
    let path = std::fs::canonicalize(path)
        .map_err(|e| AppError::Usage(format!("{}: {e}", path.display())))?;
    let name = path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let mut client = crate::room_cli::attach(&paths).await?;
    println!(
        "vox: about to send {name} out of session {label}'s Session: the members node {node} \
         trusts with drive are served it, and their nodes pull it; no one else sees it"
    );
    let note = note.map(str::trim).unwrap_or_default();
    let mut env = Envelope::new(FILE, note);
    if !note.is_empty() {
        env.data = serde_json::json!({ "note": note });
    }
    env.from.clone_from(&session);
    let shared = crate::share_cli::shares_of(
        client
            .request(&Request::SessionShare {
                channel_id,
                path: path.to_string_lossy().into_owned(),
                envelope: serde_json::to_string(&env)
                    .map_err(|e| AppError::Usage(format!("the announcement: {e}")))?,
                to: SessionTo::Session(session.clone()),
            })
            .await,
    )?;
    let row = shared
        .into_iter()
        .next()
        .ok_or_else(|| AppError::Usage("the daemon did not say what it sends".into()))?;
    println!(
        "vox: sent {} ({} bytes, sha256 {}…) out of session {label}'s Session",
        row.name,
        row.size,
        &row.sha256[..row.sha256.len().min(16)]
    );
    Ok(())
}
