//! The read-only machine anchor projection. Mutation controls extend this surface separately.

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
    if json {
        let anchors: Vec<_> = anchors
            .iter()
            .map(|anchor| {
                let sources: Vec<_> = anchor
                    .sources
                    .iter()
                    .map(|source| match source {
                        AnchorSource::AddedByHand => serde_json::json!({"kind": "added-by-hand"}),
                        AnchorSource::Room { room, name, stale } => serde_json::json!({
                            "kind": "room", "room": b32_encode(room), "name": name, "stale": stale,
                        }),
                    })
                    .collect();
                serde_json::json!({
                    "fingerprint": b32_encode(&anchor.fingerprint),
                    "addresses": anchor.addresses,
                    "sources": sources,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({"schema": "vox.anchor.list/1", "anchors": anchors})
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
                "{}  {}  {}",
                b32_encode(&anchor.fingerprint)
                    .chars()
                    .take(12)
                    .collect::<String>(),
                anchor.addresses.join(", "),
                sources.join("; ")
            );
        }
    }
    Ok(())
}
