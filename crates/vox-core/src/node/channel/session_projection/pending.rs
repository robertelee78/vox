//! Owned governance and published-view continuations. Store writer admission belongs only
//! to `run`; preparation and exact-owner installation never acquire it.
use super::super::{entry_store, governance, history, ChannelState};
use super::source::SourcePolicy;
use crate::atrest::sek::WeakSek;
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;
use crate::node::store::Store;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(crate) enum ProjectionWork {
    Governance,
    RoomViews,
    /// Schedule only after the owned private-Session maintenance step returned Complete
    /// and `needs_session_upgrade()` is false, exactly as the former advance_sessions gate.
    Sessions,
}

pub(crate) enum ProjectionProgress {
    Governance(governance::GovernanceProgress),
    RoomViews { more: bool, finished: bool },
    Sessions { advanced: bool },
}

/// Only one source basis travels to the native worker; these payloads never coexist.
enum ProjectionInput {
    Governance {
        semantic: governance::SemanticWork,
        display: Option<governance::Display>,
    },
    Sessions(crate::log::dag::Dag),
    RoomViews,
}

pub(crate) struct PendingProjection {
    owner: Option<Arc<()>>,
    room: Digest32,
    epoch: u64,
    sek: WeakSek,
    root: Digest32,
    me: Digest32,
    authors: BTreeMap<Digest32, CompositePublicKey>,
    policy: SourcePolicy,
    now: u64,
    paused_views: bool,
    work: ProjectionWork,
    entries: entry_store::EntryIndex,
    input: ProjectionInput,
    history_pin: Option<history::PendingHistoryRead>,
}

pub(crate) struct CompletedProjection {
    pending: PendingProjection,
    entries_changed: bool,
    pub(crate) result: Result<ProjectionProgress>,
}

impl CompletedProjection {
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.pending.history_pin.take()
    }

    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        channel.channel_id == self.pending.room
            && channel.epoch == self.pending.epoch
            && self
                .pending
                .owner
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, owner))
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
}

impl ChannelState {
    pub(crate) fn prepare_pending_projection(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        work: ProjectionWork,
        now: crate::time::Ms,
    ) -> Result<PendingProjection> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        // The legacy cache-only check is a committed read. No no-op derived batch
        // (including room-view readiness checks) is allowed in this preparation.
        let paused_views =
            matches!(work, ProjectionWork::RoomViews) && self.legacy_cache_only(store)?;
        self.now_hint = self.now_hint.max(now.get());
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(PendingProjection {
            owner: Some(owner),
            room: self.channel_id,
            epoch: self.epoch,
            sek: self.sek.reader(),
            root: self.genesis.creator_pubkey().fingerprint(),
            me: self.me(),
            authors: if matches!(work, ProjectionWork::Governance) {
                self.authors.clone()
            } else {
                BTreeMap::new()
            },
            policy: SourcePolicy {
                retention: self.effective_retention(),
                step_retention: self.effective_step_retention(),
            },
            now: now.get(),
            work,
            entries: entry_store::EntryIndex::default(),
            history_pin: Some(pin),
            paused_views,
            input: match work {
                ProjectionWork::Governance => ProjectionInput::Governance {
                    semantic: self
                        .governance_semantic
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take_work(),
                    display: Some(governance::Display::genesis(&self.genesis)),
                },
                ProjectionWork::Sessions => {
                    ProjectionInput::Sessions(self.dag.authored_candidate())
                }
                ProjectionWork::RoomViews => ProjectionInput::RoomViews,
            },
        })
    }

    /// The dispatcher additionally checks the retained room pointer and attachment and
    /// retains the original Computer publication lease through this matching install.
    pub(crate) fn finish_pending_projection(
        &mut self,
        store: &Store,
        completed: CompletedProjection,
    ) -> Result<ProjectionProgress> {
        if !completed
            .pending
            .owner
            .as_ref()
            .is_some_and(|owner| completed.can_install(self, owner))
        {
            return completed.result;
        }
        self.install_projection_result(store, completed)
    }

    fn install_projection_result(
        &mut self,
        _store: &Store,
        completed: CompletedProjection,
    ) -> Result<ProjectionProgress> {
        if completed.entries_changed {
            self.entries.committed();
        }
        let CompletedProjection {
            mut pending,
            result,
            ..
        } = completed;
        let result = result.and_then(|progress| {
            let ProjectionProgress::Governance(mut progress) = progress else {
                return Ok(progress);
            };
            let expired = matches!(&pending.input,
                ProjectionInput::Governance { display: Some(display), .. }
                    if display.valid_until != 0 && self.now_hint >= display.valid_until);
            if progress.ready && expired {
                self.governance_ready = false;
                progress.ready = false;
                progress.pending = true;
                return Ok(ProjectionProgress::Governance(progress));
            }
            let ProjectionInput::Governance {
                semantic,
                mut display,
            } = std::mem::replace(&mut pending.input, ProjectionInput::RoomViews)
            else {
                return Err(Error::MalformedAtRest("governance semantic worker missing"));
            };
            let installed = self
                .governance_semantic
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .install(semantic);
            if !installed {
                progress.ready = false;
                progress.pending = true;
                return Ok(ProjectionProgress::Governance(progress));
            }
            if progress.ready {
                let display = display
                    .take()
                    .ok_or(Error::MalformedAtRest("governance display worker missing"))?;
                progress.changed =
                    self.governance_display.revision != display.revision || !self.governance_ready;
                self.governance_display = display;
                self.governance_ready = true;
            }
            Ok(ProjectionProgress::Governance(progress))
        });
        if let Some(owner) = &pending.owner {
            self.release_pending_text(owner, false);
        }
        if let Err(error) = &result {
            if !matches!(pending.work, ProjectionWork::Governance) || !governance::refreshing(error)
            {
                self.poison(error);
            }
        }
        self.history_publication_changed.notify_waiters();
        result
    }
    /// Source::write_owned reserves and pins after this committed-read-only callback.
    pub(crate) fn prepare_history_governance_projection(
        &self,
        now: crate::time::Ms,
    ) -> Result<PendingProjection> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        Ok(PendingProjection {
            owner: None,
            room: self.channel_id,
            epoch: self.epoch,
            sek: self.sek.reader(),
            root: self.genesis.creator_pubkey().fingerprint(),
            me: self.me(),
            authors: self.authors.clone(),
            policy: SourcePolicy {
                retention: self.effective_retention(),
                step_retention: self.effective_step_retention(),
            },
            now: now.get(),
            work: ProjectionWork::Governance,
            paused_views: false,
            entries: entry_store::EntryIndex::default(),
            history_pin: None,
            input: ProjectionInput::Governance {
                semantic: self
                    .governance_semantic
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take_work(),
                display: Some(governance::Display::genesis(&self.genesis)),
            },
        })
    }

    /// Only the matching Source::write_owned install callback calls this: Source owns
    /// room-instance/epoch/owner checks and releases its own reservation after install.
    pub(crate) fn finish_history_governance_projection(
        &mut self,
        store: &Store,
        completed: CompletedProjection,
    ) -> Result<()> {
        self.now_hint = self.now_hint.max(completed.pending.now);
        self.install_projection_result(store, completed).map(|_| ())
    }
}

impl PendingProjection {
    /// Run in the native blocking pool, outside room/actor/Computer.state. Persisted
    /// fold/build cursors and every original bounded helper remain the sole continuation.
    pub(crate) fn run(mut self, store: &Store) -> CompletedProjection {
        let sek = self.sek.clone();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sek.with(|sek| match self.work {
                ProjectionWork::Governance => {
                    let progress = governance::advance(
                        store,
                        &self.entries,
                        sek,
                        &self.room,
                        &self.authors,
                        &self.root,
                        &self.me,
                        self.now,
                    )?;
                    let mut ready = progress.ready;
                    if ready {
                        let view =
                            governance::View::open(store, sek, &self.room, self.root, self.now)?;
                        let ProjectionInput::Governance { semantic, display } = &mut self.input
                        else {
                            return Err(Error::MalformedAtRest(
                                "governance semantic worker missing",
                            ));
                        };
                        ready = semantic.advance(&view)?;
                        let basis = display
                            .take()
                            .ok_or(Error::MalformedAtRest("governance display basis missing"))?;
                        *display = Some(view.display_from(basis)?);
                    }
                    Ok(ProjectionProgress::Governance(
                        governance::GovernanceProgress {
                            ready,
                            pending: progress.pending || (progress.ready && !ready),
                            changed: false,
                        },
                    ))
                }
                ProjectionWork::RoomViews => {
                    if self.paused_views {
                        return Ok(ProjectionProgress::RoomViews {
                            more: false,
                            finished: false,
                        });
                    }
                    let was_ready = self
                        .entries
                        .render_view(store, sek, &self.room)?
                        .room_views_ready()?;
                    let more = self.entries.advance_room_views(store, sek, &self.room)?;
                    Ok(ProjectionProgress::RoomViews {
                        more,
                        finished: !was_ready && !more,
                    })
                }
                ProjectionWork::Sessions => {
                    let ProjectionInput::Sessions(dag) = &self.input else {
                        return Err(Error::MalformedAtRest(
                            "Session projection source basis missing",
                        ));
                    };
                    let metadata = super::build::advance_owned(
                        &self.entries,
                        dag,
                        store,
                        sek,
                        &self.room,
                        self.policy,
                        self.now,
                    )?;
                    let activity = super::activity_fold::advance_owned(store, sek, &self.room)?;
                    let waiting = super::waiting::advance_owned(store, sek, &self.room)?;
                    Ok(ProjectionProgress::Sessions {
                        advanced: metadata || activity || waiting,
                    })
                }
            })
        }))
        .unwrap_or_else(|_| Err(Error::Profile("room projection worker failed")));
        let entries_changed = self.entries.commit_generation() != 0;
        CompletedProjection {
            pending: self,
            entries_changed,
            result,
        }
    }
}
