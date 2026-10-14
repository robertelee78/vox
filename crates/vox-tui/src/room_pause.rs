//! CLI/TUI consumers of the shared bounded room pause protocol (ADR-033 PA-1).

use crate::app::AppError;
use vox_core::hash::Digest32;
use vox_core::node::ipc::{Frame, NodeSocket};
use vox_core::node::paths::Paths;
use vox_core::node::room_pause::{Failure, Selection};

async fn targets(
    paths: &Paths,
    room: Digest32,
    names: &[String],
) -> Result<(NodeSocket, Selection, Vec<Result<Digest32, String>>), AppError> {
    let at = crate::client::one_shot(paths)?;
    let selected = vox_core::node::room_pause::capture(&at, room)
        .await
        .map_err(AppError::Usage)?;
    if names.len() > vox_core::node::channel::AUTHORS_HARD_LIMIT {
        return Err(AppError::Usage(
            "the selection has more nodes than a room can hold".into(),
        ));
    }
    let targets = if names.is_empty() {
        selected.members.iter().copied().map(Ok).collect()
    } else {
        let mut client = crate::room_cli::attach(paths).await?;
        let trusted = match client.trusted("").await {
            Ok(Frame::Trusted { entries }) => crate::ident::names_of(entries),
            Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
            Ok(other) => return Err(crate::client::unexpected(&other)),
            Err(e) => return Err(AppError::Usage(e.to_string())),
        };
        let mut targets = Vec::new();
        for name in names {
            let target = if matches!(name.as_str(), "me" | "you") {
                Ok(selected.actor)
            } else {
                crate::ident::resolve_member(name, &selected.members, &trusted)
            };
            if !targets.contains(&target) {
                targets.push(target);
            }
        }
        targets
    };
    Ok((at, selected, targets))
}

/// One CLI action processes all targets and every interrupt continuation without another click.
/// Four receivers may work at once; each page is printed immediately, not collected as history.
///
/// # Errors
/// Setup failed, or any selected node/interrupt was refused, unsent or unknown.
pub async fn run(
    paths: &Paths,
    room: &str,
    names: &[String],
    paused: bool,
    json: bool,
) -> Result<(), AppError> {
    use futures_util::StreamExt as _;
    let mut client = crate::room_cli::attach(paths).await?;
    let room = crate::room_cli::room_of(&mut client, room).await?;
    let (at, selected, targets) = targets(paths, room, names).await?;
    let mut results = futures_util::stream::iter(targets).map(|target| {
        let (at, selected) = (&at, &selected);
        async move {
            let peer = match target {
                Ok(peer) => peer,
                Err(why) => {
                    if json { println!("{}", serde_json::json!({"schema":"vox.room.pause/1", "outcome":"not sent", "reason":why})); }
                    else { println!("{why}; not sent"); }
                    return true;
                }
            };
            let label = vox_core::node::link::b32_encode(&peer);
            let result = change_target(at, selected, peer, paused, |report| {
                if json {
                    println!("{}", serde_json::json!({"schema":"vox.room.pause/1", "node":label, "admitted":true, "report":report}));
                } else {
                    let state = report.selection.state;
                    if state.at_millis == 0 {
                        println!("{label}: Resumed (no pause has been set)");
                    } else {
                        println!("{label}: {} (by {}, at {} ms)", if state.paused { "Paused" } else { "Resumed" },
                            vox_core::node::link::b32_encode(&state.by), state.at_millis);
                    }
                    for item in &report.interrupts { println!("  {label}/{}: {}", item.session, item.said); }
                    if let Some(error) = &report.interrupt_error { println!("  {label}: state saved; interrupts incomplete: {error}"); }
                }
            }).await;
            if let Some(error) = &result.request_error {
                if json { println!("{}", serde_json::json!({"schema":"vox.room.pause/1", "node":label, "outcome":failure_kind(error), "reason":error.to_string(), "earlier_state_saved":result.saved})); }
                else { println!("{label}: {}: {error}{}", failure_kind(error), if result.saved { "; earlier acknowledged state remains saved" } else { "" }); }
            }
            result.failed != 0 || result.discovery_error.is_some() || result.request_error.is_some()
        }
    }).buffer_unordered(4);
    let mut failed = false;
    while let Some(result) = results.next().await {
        failed |= result;
    }
    if failed {
        Err(AppError::Usage("room operation finished with the named refusals, incomplete interrupts or unknown outcomes; acknowledged state remains saved".into()))
    } else {
        Ok(())
    }
}

fn failure_kind(error: &Failure) -> &'static str {
    match error {
        Failure::Refused(_) => "refused",
        Failure::NotSent(_) => "not sent",
        Failure::Unknown(_) => "outcome unknown",
    }
}

#[derive(Default)]
struct TargetResult {
    saved: bool,
    delivered: u64,
    failed: u64,
    first_failed: Option<String>,
    discovery_error: Option<String>,
    request_error: Option<Failure>,
}

/// One target's pages are consumed before its slot is released. Only scalar counts and one
/// explicitly named example of an interrupt failure survive a page; CLI prints all results.
async fn change_target(
    at: &NodeSocket,
    selected: &Selection,
    peer: Digest32,
    paused: bool,
    mut page: impl FnMut(&vox_agentcomms::drive::PauseReport),
) -> TargetResult {
    let mut result = TargetResult::default();
    let mut continuation = None;
    loop {
        match vox_core::node::room_pause::change(at, selected, peer, paused, continuation).await {
            Ok(report) => {
                page(&report);
                result.saved = true;
                for item in report.interrupts {
                    if item.delivered {
                        result.delivered = result.delivered.saturating_add(1);
                    } else {
                        result.failed = result.failed.saturating_add(1);
                        result
                            .first_failed
                            .get_or_insert_with(|| format!("{}: {}", item.session, item.said));
                    }
                }
                if let Some(error) = report.interrupt_error {
                    result.discovery_error = Some(error);
                    return result;
                }
                continuation = report.next.map(|next| (next, report.selection));
                if continuation.is_none() {
                    return result;
                }
            }
            Err(error) => {
                result.request_error = Some(error);
                return result;
            }
        }
    }
}

/// TUI's one-action report: one line per selected current node. Four receivers run at once;
/// the report is bounded by the current roster and displayed in a scrollable result view.
///
/// # Errors
/// The selected node/room cannot be captured or named.
pub async fn summarize(
    paths: &Paths,
    room: Digest32,
    names: &[String],
    paused: bool,
) -> Result<Vec<String>, AppError> {
    use futures_util::StreamExt as _;
    let (at, selected, targets) = targets(paths, room, names).await?;
    let lines: Vec<String> = futures_util::stream::iter(targets)
        .map(|target| {
            let (at, selected) = (&at, &selected);
            async move {
                let peer = match target {
                    Ok(peer) => peer,
                    Err(why) => return format!("{why}; not sent"),
                };
                let label = vox_core::node::link::b32_encode(&peer);
                let result = change_target(at, selected, peer, paused, |_| {}).await;
                let state = if result.saved {
                    if paused {
                        "Paused (saved)"
                    } else {
                        "Resumed (saved)"
                    }
                } else {
                    "no saved state acknowledged"
                };
                let mut line = format!(
                    "{label}: {state}; {} interrupted, {} not acknowledged",
                    result.delivered, result.failed
                );
                if let Some(error) = result.request_error {
                    line.push_str(&format!("; {}: {error}", failure_kind(&error)));
                }
                if let Some(error) = result.discovery_error {
                    line.push_str(&format!("; interruption incomplete: {error}"));
                }
                if let Some(first) = result.first_failed {
                    line.push_str(&format!("; first interruption failure: {first}"));
                }
                line
            }
        })
        .buffered(4)
        .collect()
        .await;
    Ok(lines)
}

/// Coordinate only final hook output with pause admission. Try-locking never blocks a Tokio
/// worker; the lock contains no state and all slow news reads happen before it is acquired.
/// The exclusive owner passes its file into the actor command instead of waiting in the actor.
pub(crate) async fn publication_lock(
    paths: &Paths,
    room: Digest32,
    exclusive: bool,
) -> Result<std::fs::File, String> {
    let dir = paths.cursor_dir().join("pause-locks");
    vox_core::node::paths::create_private_dir(&dir).map_err(|error| error.to_string())?;
    let path = dir.join(vox_core::node::link::b32_encode(&room));
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|error| error.to_string())?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let result = if exclusive {
            file.try_lock()
        } else {
            file.try_lock_shared()
        };
        match result {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::Error(error)) => return Err(error.to_string()),
            Err(std::fs::TryLockError::WouldBlock) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err("room news publication is busy; try again".into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}
