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
    sources: Option<crate::log::dag::Dag>,
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
            sources: matches!(work, ProjectionWork::Sessions)
                .then(|| self.dag.authored_candidate()),
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
        store: &Store,
        completed: CompletedProjection,
    ) -> Result<ProjectionProgress> {
        if completed.entries_changed {
            self.entries.committed();
        }
        let CompletedProjection {
            pending, result, ..
        } = completed;
        let result = result.and_then(|progress| {
            let ProjectionProgress::Governance(mut progress) = progress else {
                return Ok(progress);
            };
            // These are checked reads only. Keep the established display/consent
            // publication order and the admitted-pair cursor on ChannelState; no
            // retained-history or consent projection clone crosses the worker.
            if progress.ready {
                let was_ready = self.governance_ready;
                let view = self.checked_governance(store, pending.now)?;
                let display = view.display(&self.genesis)?;
                let consent_ready = self.advance_consent_facts(&view)?;
                progress.changed = self.governance_display.revision != display.revision
                    || (!was_ready && consent_ready);
                self.governance_display = display;
                self.governance_ready = consent_ready;
                progress.ready = consent_ready;
                progress.pending |= !consent_ready;
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
            sources: None,
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
    pub(crate) fn run(self, store: &Store) -> CompletedProjection {
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
                    Ok(ProjectionProgress::Governance(
                        governance::GovernanceProgress {
                            ready: progress.ready,
                            pending: progress.pending,
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
                    let dag = self.sources.as_ref().ok_or(Error::MalformedAtRest(
                        "Session projection source basis missing",
                    ))?;
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
