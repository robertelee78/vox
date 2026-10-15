//! The tasks an attached node runs beside its actor (ADR-026 L-2): the notifier,
//! and the interrupt path (wake, ping and tend). Each is cancellable, so a node can be detached
//! without stopping the daemon: [`NodeTasks::stop`] ends them before the node's own stop.
//!
//! Manual anchor refresh belongs to the daemon's machine registry, rather than these node tasks.

use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use vox_core::node::actor::NodeHandle;
use vox_core::node::paths::Paths;

/// The tasks of one attached node, and the token that ends them.
pub struct NodeTasks {
    cancel: CancellationToken,
    set: tokio::task::JoinSet<()>,
}

impl NodeTasks {
    /// Start `node`'s tasks on `rt`: the notifier, and the interrupt path.
    #[must_use]
    pub fn start(rt: &Handle, node: &NodeHandle, paths: &Paths) -> Self {
        let cancel = CancellationToken::new();
        let mut set = tokio::task::JoinSet::new();
        let mut spawn = |task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>| {
            let cancel = cancel.clone();
            set.spawn_on(
                async move {
                    tokio::select! {
                        () = cancel.cancelled() => {}
                        () = task => {}
                    }
                },
                rt,
            );
        };
        // Tell the operator when `vox status` would flag something, and when it clears
        // (PRD-001 R37). Off with `notify = off` in the profile's config file.
        spawn(Box::pin(crate::notify::watch(node.clone(), paths.clone())));
        spawn(Box::pin(watch_for_interrupts(node.clone(), paths.clone())));
        Self { cancel, set }
    }

    /// End every task and wait for each to finish. A task ends at its next await once cancelled;
    /// owned attention tasks are cancelled too; their sealed attempts remain explicitly uncertain.
    pub async fn stop(mut self) {
        self.cancel.cancel();
        while self.set.join_next().await.is_some() {}
    }
}

/// Fair bounded inspection of the existing room/Session indexes. Only one cursor per
/// configured room and at most four in-flight adapter submissions are resident.
async fn watch_for_interrupts(node: NodeHandle, paths: Paths) {
    use vox_core::node::attention::{DispatchOutcome, Operation, Reply, State, Wait};
    let mut events = node.subscribe();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
    let mut recipients = std::collections::HashMap::new();
    let mut pings = std::collections::HashMap::new();
    let mut said_above = std::collections::HashMap::new();
    let mut sends = tokio::task::JoinSet::new();
    // Only the existing four adapter slots retain a selection; lookup is not a new queue.
    let mut submitting = std::collections::HashMap::<tokio::task::Id, ([u8; 32], String)>::new();
    let mut next_room = 0usize;
    let history = node.history_reader();
    let deaf = wake_deaf();
    loop {
        tokio::select! {
            item = events.next() => match item {
                None => return,
                Some(vox_core::node::actor::EventStreamItem::Event(event)) => {
                    crate::tunnel_cli::say_failure_for_node(&event, paths.profile_dir.file_name().and_then(|n| n.to_str()));
                }
                Some(vox_core::node::actor::EventStreamItem::Lagged(_)) => {}
            },
            _ = tick.tick() => {},
            Some(done) = sends.join_next_with_id(), if !sends.is_empty() => {
                let id = match done { Ok((id, ())) => id, Err(error) => error.id() };
                submitting.remove(&id);
            },
        }
        let view = node.view();
        say_retention_above_room(&view, &mut said_above, &paths);
        let Some(owner) = view.identity.as_ref().map(|identity| identity.fingerprint) else {
            continue;
        };
        recipients.retain(|room, _| view.open_channels.iter().any(|d| d.channel_id == *room));
        pings.retain(|room, _| view.open_channels.iter().any(|d| d.channel_id == *room));
        let rooms = view.open_channels.len();
        if rooms == 0 {
            next_room = 0;
            continue;
        }
        let start = next_room % rooms;
        for offset in 0..rooms {
            let index = (start + offset) % rooms;
            let detail = &view.open_channels[index];
            let room = detail.channel_id;
            if !deaf {
                let _ = node
                    .attention(
                        room,
                        owner,
                        Some(detail.history_instance),
                        Operation::Maintain,
                    )
                    .await;
            }
            if detail.pause.paused {
                continue;
            }
            if !pings.contains_key(&room) {
                if let Ok(head) = history.arrival_head(room).await {
                    if let Ok(_publication) =
                        crate::room_pause::publication_lock(&paths, room, false).await
                    {
                        if !room_held(&node.view(), &room) {
                            pings.insert(room, head);
                        }
                    }
                }
            } else if let Ok(page) = history
                .arrival_page(room, pings.get(&room).copied(), 64)
                .await
            {
                let Ok(_publication) =
                    crate::room_pause::publication_lock(&paths, room, false).await
                else {
                    continue;
                };
                if room_held(&node.view(), &room) {
                    continue;
                }
                for row in page.rows {
                    if crate::ping::is_ping(&row.text) {
                        crate::ping::answer(&node, &paths, &view, room, &row);
                    }
                    pings.insert(
                        room,
                        vox_core::node::api::HistoryCursor {
                            instance: page.instance,
                            arrival: row.arrival,
                        },
                    );
                }
                if let Some(next) = page.next {
                    pings.insert(room, next);
                }
            }
            if deaf {
                continue;
            }
            let page = node
                .attention(
                    room,
                    owner,
                    None,
                    Operation::Recipients {
                        after: recipients.get(&room).copied().flatten(),
                    },
                )
                .await;
            let (selected, next) = match page {
                Ok(Reply::Recipients { recipients, next }) => (recipients, next),
                Err(reason) => {
                    eprintln!("vox daemon: attention selection remains pending: {reason}");
                    recipients.remove(&room);
                    continue;
                }
                _ => continue,
            };
            recipients.insert(room, next);
            for recipient in selected {
                let room_text = vox_core::node::link::b32_encode(&room);
                let session = match crate::wake::pause_registration(&paths, &recipient.session) {
                    Ok(Some(session))
                        if session.interactive
                            && session.room.as_deref() == Some(room_text.as_str()) =>
                    {
                        session
                    }
                    _ => continue,
                };
                if submitting.values().any(|(active_room, active_session)| {
                    *active_room == room && active_session == &recipient.session
                }) {
                    continue;
                }
                // Registration establishes this durable cursor before its caller receives ACK.
                // Restart or idle route refresh never resets an existing recipient's cursor.
                if node
                    .attention(
                        room,
                        owner,
                        Some(recipient.instance),
                        Operation::Resolve {
                            session: recipient.session.clone(),
                        },
                    )
                    .await
                    .is_err()
                {
                    continue;
                }
                if let Err(reason) = node
                    .attention(
                        room,
                        owner,
                        Some(recipient.instance),
                        Operation::Scan {
                            recipient: recipient.clone(),
                            harness: session.harness.clone(),
                            route: session.attention.as_ref().map(|route| route.route),
                        },
                    )
                    .await
                {
                    eprintln!("vox daemon: attention source scan remains pending: {reason}");
                    continue;
                }
                if sends.len() >= 4 || room_held(&node.view(), &room) {
                    continue;
                }
                if session.harness != "opencode" {
                    continue;
                }
                let page = match node
                    .attention(
                        room,
                        owner,
                        Some(recipient.instance),
                        Operation::Pending {
                            recipient: recipient.clone(),
                        },
                    )
                    .await
                {
                    Ok(Reply::Page(page)) => page,
                    _ => continue,
                };
                let sources: Vec<_> = page
                    .rows
                    .iter()
                    .filter(|row| {
                        row.state == State::Queued
                            && matches!(row.wait, None | Some(Wait::AdapterUnavailable))
                    })
                    .map(|row| row.source)
                    .collect();
                if sources.is_empty() {
                    continue;
                }
                let label = detail.name.as_deref().unwrap_or(&room_text).to_owned();
                let (node, paths, expected_pause) = (node.clone(), paths.clone(), detail.pause);
                // A freed adapter slot goes first to the next room. A slow client lookup
                // stays inside that slot and cannot hold the shared room scanner.
                next_room = (index + 1) % rooms;
                let key = (room, recipient.session.clone());
                let task = sends.spawn(async move {
                    let mut watch = node.watch();
                    let held = async {
                        loop {
                            if watch.borrow().open_channels.iter().find(|d| d.channel_id == room).is_none_or(|d| d.pause != expected_pause || d.pause.paused || d.history_instance != recipient.instance) || watch.borrow().locked || watch.borrow().locking { return; }
                            if watch.changed().await.is_err() { return; }
                        }
                    };
                    tokio::pin!(held);
                    let route = tokio::select! {
                        biased;
                        () = &mut held => return,
                        result = crate::wake::current_attention(&paths, &session) => match result {
                            Ok(route) => route,
                            Err(_) => return,
                        },
                    };
                    // Availability comes from the exact live-client handshake, not the last
                    // client that happened to register this saved Session. The actor still
                    // checks this opening/room incarnation and pause authority for every step.
                    if node.attention(room, owner, Some(recipient.instance), Operation::Scan {
                        recipient: recipient.clone(), harness: session.harness.clone(),
                        route: route.as_ref().map(|r| r.route),
                    }).await.is_err() { return; }
                    let Some(route) = route else { return };
                    let attempt = match node.attention(room, owner, Some(recipient.instance),
                        Operation::Begin { recipient: recipient.clone(), route: route.route, sources }).await {
                        Ok(Reply::Attempt(Some(attempt))) => attempt,
                        _ => return,
                    };
                    let text = format!("Vox notice: a batch of {} unread room message(s) is queued for this Session in {}. Their attributed text and source references arrive through the ordinary Vox hook. This notice contains no operator request or room-message body.", attempt.count, vox_text::shown(&label, 128));
                    // This is the existing pause-publication fence. No actor IPC is awaited
                    // while held; a pause either precedes this submission or reports busy.
                    let outcome = match crate::room_pause::publication_lock(&paths, room, false).await {
                        Err(reason) => DispatchOutcome::Held(reason),
                        Ok(_publication) if room_held(&node.view(), &room) => DispatchOutcome::Held("room news is paused before submission".into()),
                        Ok(_publication) => tokio::select! {
                            biased;
                            () = &mut held => DispatchOutcome::Unknown("room authority/pause changed while submission was pending; no retry without receipt".into()),
                            outcome = crate::wake::attention_on_route(&paths, &session, &route, attempt.notice_id, &text) => outcome,
                        },
                    };
                    if let Err(error) = node.attention(room, owner, Some(recipient.instance), Operation::Dispatch { attempt, outcome }).await {
                        eprintln!("vox daemon: attention outcome was not saved; reserved notice remains uncertain: {error}");
                    }
                });
                submitting.insert(task.id(), key);
            }
            tokio::task::yield_now().await;
        }
    }
}

/// Missing, closed or paused rooms hold autonomous attention. Human drive stays independent.
fn room_held(view: &vox_core::node::api::NodeView, room: &vox_core::hash::Digest32) -> bool {
    view.locked
        || view.locking
        || view
            .open_channels
            .iter()
            .find(|d| d.channel_id == *room)
            .is_none_or(|d| d.pause.paused)
}

/// Say, once each, every room whose retention this node's own file asks to exceed (V030-32).
fn say_retention_above_room(
    view: &vox_core::node::api::NodeView,
    said: &mut std::collections::HashMap<vox_core::hash::Digest32, (u64, u64)>,
    paths: &Paths,
) {
    said.retain(|room, _| {
        view.open_channels
            .iter()
            .any(|d| d.channel_id == *room && d.retention_above_room.is_some())
    });
    for d in &view.open_channels {
        if let Some((asked, room)) = d.retention_above_room {
            if said.insert(d.channel_id, (asked, room)) != Some((asked, room)) {
                crate::tunnel_cli::say_failure_for_node(
                    &vox_core::node::api::NodeEvent::RetentionAboveRoom {
                        channel_id: d.channel_id,
                        node: asked,
                        room,
                    },
                    paths.profile_dir.file_name().and_then(|n| n.to_str()),
                );
            }
        }
    }
}

/// **Test-only: a wake loop that judges and sends nothing** (V030-31, #368), read from
/// `VOX_TEST_WAKE_DEAF=1` in a build with the `test-knobs` feature; no shipped build reads it
/// (V210-105). It stages the one window the startup count guards: an urgent row in the node's
/// store that the wake loop never looked at before the daemon was killed. Rows still land and are
/// stored; only the loop's judging and sending are off, and the daemon says so at start.
fn wake_deaf() -> bool {
    #[cfg(feature = "test-knobs")]
    if std::env::var("VOX_TEST_WAKE_DEAF").is_ok_and(|v| v.trim() == "1") {
        eprintln!(
            "vox daemon: test-knobs: the wake loop judges and sends nothing (VOX_TEST_WAKE_DEAF)"
        );
        return true;
    }
    false
}
