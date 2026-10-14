//! Durable room pause admission, followed by bounded live-Session interruption.

use super::{lock, NodeHandle, NodeName, Router, Slot};
use std::sync::Arc;
use vox_agentcomms::drive::{
    Action, Answer, PauseInterrupt, PauseReport, PauseSelection, PAUSE_PAGE,
};

impl Router {
    /// The peer is from the authenticated app stream, never from JSON. Continuations bind
    /// to the existing saved-room instance and exact state so a resumed room is not interrupted.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn pause_room(
        &self,
        node: &NodeName,
        handle: &NodeHandle,
        info: &vox_core::node::app::AppInfo,
        generation: u64,
        paused: Option<bool>,
        after: Option<&str>,
        expected: Option<PauseSelection>,
    ) -> Answer {
        let refuse = |said: String| Answer {
            ok: false,
            said,
            code: None,
            pause: None,
        };
        if after.is_some() != expected.is_some() || (after.is_some() && paused != Some(true)) {
            return refuse("invalid room pause continuation; refresh the room".into());
        }
        // Never acquire this inside the serialized actor: a hook holding shared access
        // must still be able to ask that actor for its final current state. Move the owned
        // fence into the command so cancellation after enqueue cannot release it early.
        let publication_guard = if paused.is_some() && after.is_none() {
            let paths = match self.inner.account.node_paths(node) {
                Ok(paths) => paths,
                Err(error) => return refuse(error.to_string()),
            };
            match crate::room_pause::publication_lock(&paths, info.channel_id, true).await {
                Ok(guard) => Some(guard),
                Err(error) => return refuse(format!("room pause was not changed: {error}")),
            }
        } else {
            None
        };
        let selection =
            match handle
                .room_pause(
                    info.channel_id,
                    info.peer,
                    if after.is_some() { None } else { paused },
                    expected,
                    publication_guard,
                )
                .await
            {
                Ok(selection) => selection,
                Err(super::Fault::Storage | super::Fault::Internal) => return Answer {
                    ok: false,
                    said:
                        "the node could not confirm its saved pause state; the outcome is unknown"
                            .into(),
                    code: Some(vox_agentcomms::drive::PAUSE_UNKNOWN.into()),
                    pause: None,
                },
                Err(fault) => return refuse(fault.explain().to_owned()),
            };
        let mut report = PauseReport {
            selection,
            interrupts: Vec::new(),
            next: None,
            interrupt_error: None,
        };
        if paused == Some(true) {
            let paths = match self.inner.account.node_paths(node) {
                Ok(paths) => paths,
                Err(e) => {
                    report.interrupt_error = Some(e.to_string());
                    return saved(report);
                }
            };
            let room = vox_core::node::link::b32_encode(&info.channel_id);
            let registrations = match crate::wake::registered_page(&paths, &room, after, PAUSE_PAGE)
            {
                Ok(registrations) => registrations,
                Err(e) => {
                    report.interrupt_error = Some(e);
                    return saved(report);
                }
            };
            report.next = registrations.1;
            // Each turn retains one small live-registration page, never Session history.
            // All Esc deliveries in the page run together, inside the drive request deadline.
            let mut tasks = tokio::task::JoinSet::new();
            for registration in registrations.0 {
                let (router, node, handle, paths, info) = (
                    self.clone(),
                    node.clone(),
                    handle.clone(),
                    paths.clone(),
                    info.clone(),
                );
                tasks.spawn(async move {
                    let id = registration.session.clone();
                    let current = handle.view();
                    let same = {
                        let slots = lock(&router.inner.slots);
                        matches!(slots.get(&node), Some(Slot::Attached(attached))
                            if attached.generation == generation && Arc::ptr_eq(attached.handle.app(), handle.app()) && !*attached.detached.borrow())
                    };
                    let own = current.identity.as_ref().map(|i| i.fingerprint) == Some(info.peer);
                    let ready = same && !current.locked && !current.locking
                        && (own || current.drive.contains(&info.peer))
                        && current.open_channels.iter().any(|d| d.channel_id == info.channel_id
                            && d.history_instance == selection.instance && d.pause == selection.state && d.pause.paused)
                        && crate::wake::pause_registration(&paths, &id).ok().flatten().is_some_and(|now| now.same(&registration)
                            && now.first_seen_ms == registration.first_seen_ms && now.tmux == registration.tmux
                            && now.codex_home == registration.codex_home && now.mirror == registration.mirror);
                    let outcome = if !ready {
                        Err("the room, pause, authority or Session changed; no interrupt was sent".into())
                    } else {
                        let mut views = handle.watch();
                        let changed = async {
                            loop {
                                let valid = {
                                    let view = views.borrow();
                                    let owns = view.identity.as_ref().map(|i| i.fingerprint) == Some(info.peer);
                                    !view.locked && !view.locking && (owns || view.drive.contains(&info.peer))
                                        && view.open_channels.iter().any(|d| d.channel_id == info.channel_id
                                            && d.history_instance == selection.instance && d.pause == selection.state && d.pause.paused)
                                };
                                if !valid || views.changed().await.is_err() { return; }
                            }
                        };
                        tokio::select! {
                            biased;
                            () = changed => Err("the room pause or authority changed while interrupting; delivery is unknown".into()),
                            result = tokio::time::timeout(std::time::Duration::from_secs(15), router.steer(&node, &registration, &Action::Interrupt)) => match result {
                                Ok(result) => result,
                                Err(_) => Err("the interrupt was not acknowledged in time; its delivery is unknown".into()),
                            }
                        }
                    };
                    PauseInterrupt { session: id, delivered: outcome.is_ok(), said: match outcome { Ok(s) | Err(s) => s } }
                });
            }
            while let Some(result) = tasks.join_next().await {
                match result {
                    Ok(result) => report.interrupts.push(result),
                    Err(e) => {
                        report.interrupt_error = Some(format!(
                            "an interrupt task ended without a result: {e}; delivery is unknown"
                        ))
                    }
                }
            }
            report.interrupts.sort_by(|a, b| a.session.cmp(&b.session));
        }
        saved(report)
    }
}

fn saved(report: PauseReport) -> Answer {
    Answer {
        ok: true,
        said: if report.selection.state.paused {
            "Paused: room news and wakes are held; direct operator input still works"
        } else {
            "Resumed: held news is available next turn; ordinary news starts no new turn"
        }
        .into(),
        code: None,
        pause: Some(report),
    }
}
