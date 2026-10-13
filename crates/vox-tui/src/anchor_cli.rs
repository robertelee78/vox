//! The daemon's machine anchor controls and its single provenance/reach projection.

use vox_core::node::daemonipc::{AnchorSource, DaemonClient, DaemonFrame, DaemonRequest};
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Account;

use crate::app::AppError;

/// List the running daemon's recorded manual and saved-room anchor sources. Never starts a
/// daemon or attaches a node, and never guesses whether an anchor was reached.
///
/// # Errors
/// The daemon is absent, cannot answer, or does not support this projection.
pub async fn list(account: &Account, json: bool) -> Result<(), AppError> {
    let mut client =
        DaemonClient::open_noting(&account.socket(), Some(crate::client::say_daemon_waiting))
            .await
            .map_err(|error| {
                AppError::Usage(format!("could not read the machine anchor list: {error}"))
            })?;
    let anchors = match client.request(DaemonRequest::Anchors).await? {
        DaemonFrame::Anchors(anchors) => anchors,
        DaemonFrame::Refused(why) => return Err(AppError::Usage(why.to_string())),
        _ => {
            return Err(AppError::Usage(
                "the daemon did not return its anchor list".into(),
            ))
        }
    };
    show(&anchors, json);
    Ok(())
}

/// Add/remove through the daemon's one serialized machine list.
pub async fn change(
    account: &Account,
    listen: std::net::SocketAddr,
    anchors: &[String],
    request: DaemonRequest,
) -> Result<(), AppError> {
    vox_core::node::layout::refuse_old_layout(account)?;
    crate::daemon_client::ensure_daemon(account, listen, anchors).await?;
    let mut client =
        DaemonClient::open_noting(&account.socket(), Some(crate::client::say_daemon_waiting))
            .await?;
    match client.request(request).await? {
        DaemonFrame::Anchors(anchors) => {
            show(&anchors, false);
            Ok(())
        }
        DaemonFrame::AnchorFailed(why) => Err(AppError::Usage(why)),
        DaemonFrame::Refused(why) => Err(AppError::Usage(why.to_string())),
        _ => Err(AppError::Usage(
            "the daemon did not return the changed anchor list".into(),
        )),
    }
}

fn show(anchors: &[vox_core::node::daemonipc::AnchorInfo], json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({"schema":"vox.anchor.list/1",
            "anchors":anchors.iter().map(vox_core::node::daemonipc::AnchorInfo::to_json).collect::<Vec<_>>() })
        );
    } else if anchors.is_empty() {
        println!("No manual or saved-room anchors on this machine.");
    } else {
        for anchor in anchors {
            let sources: Vec<_> = anchor
                .sources
                .iter()
                .map(|source| match source {
                    AnchorSource::AddedByHand => "added by hand".to_owned(),
                    AnchorSource::Room { room, name, stale } => format!(
                        "from room {}{}",
                        if name.is_empty() {
                            b32_encode(room).chars().take(12).collect::<String>()
                        } else {
                            name.clone()
                        },
                        if *stale {
                            " (last known; room closed, node locked or awaiting refresh)"
                        } else {
                            ""
                        }
                    ),
                })
                .collect();
            println!(
                "{}  {}  {}  {}",
                b32_encode(&anchor.fingerprint)
                    .chars()
                    .take(12)
                    .collect::<String>(),
                anchor.addresses.join(", "),
                sources.join("; "),
                anchor.reach_words(vox_core::transport::quic::unix_now_ms()),
            );
        }
    }
}
