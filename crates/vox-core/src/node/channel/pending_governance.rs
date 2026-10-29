//! Exact bounded governance cursor work. Preparation reads committed state only; native
//! writer admission and commits run without actor, room, or Computer-state ownership.
use super::semantic_projection::{PreparedContent, SemanticProjection};
use super::*;
use crate::atrest::sek::WeakSek;

pub(crate) enum Work {
    Backfill,
    Contiguous,
    ProviderPrune,
    CleanupProvisional {
        owner: legacy_provisional::LegacyProvisionalOwner,
    },
    Legacy,
    StartupCleanup,
    AdminRemoval {
        member: Digest32,
        after: Option<Digest32>,
    },
}

pub(crate) enum Saved {
    Backfill {
        rendered: usize,
        pending: bool,
        session_rendered: usize,
        placed: bool,
    },
    Contiguous {
        pending: bool,
    },
    ProviderPrune {
        pending: bool,
    },
    CleanupProvisional {
        owner: legacy_provisional::LegacyProvisionalOwner,
        complete: bool,
    },
    Legacy {
        advanced: bool,
        pending: bool,
    },
    StartupCleanup {
        blocks_current: bool,
    },
    AdminRemoval {
        count: usize,
        next: Option<Digest32>,
    },
}

impl Saved {
    pub(crate) fn needs_legacy_migration(&self) -> bool {
        matches!(self, Self::Backfill { placed: true, .. })
    }
}

enum Native {
    Backfill {
        projection: Option<Box<SemanticProjection>>,
        rows: Vec<(Entry, PreparedContent)>,
        edits: BTreeMap<Digest32, Option<u64>>,
        after: Option<Digest32>,
        refreshing: bool,
        active: bool,
        observe_now: bool,
    },
    Contiguous(Option<Digest32>),
    CleanupProvisional(legacy_provisional::LegacyProvisionalOwner),
    Provider {
        peer: Option<Digest32>,
        forget: bool,
    },
    Legacy {
        context: Box<legacy_session::LegacyProjectionContext>,
        was_pending: bool,
    },
    StartupCleanup(entry_store::Preparation),
    Admin {
        append: Option<Box<pending_text::PendingText>>,
        certificate: Option<Digest32>,
        next: Option<Digest32>,
        count: usize,
    },
}

enum Delta {
    None,
    Contiguous {
        author: Digest32,
        progress: entry_store::sparse::ContiguousAdvance,
    },
    CleanupProvisional {
        complete: bool,
    },
    Startup(entry_store::Preparation),
    Admin(Box<pending_text::CompletedText>),
}

pub(crate) struct Prepared {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    me: Digest32,
    now: crate::time::Ms,
    sek: WeakSek,
    index: entry_store::EntryIndex,
    native: Native,
    pin: Option<history::PendingHistoryRead>,
}

pub(crate) struct Completed {
    pending: Prepared,
    delta: Delta,
    committed: bool,
    pub(crate) result: Result<Saved>,
}

impl ChannelState {
    pub(crate) fn prepare_pending_governance_work(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        work: Work,
        now: crate::time::Ms,
    ) -> Result<Option<Prepared>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let native = match work {
            Work::Backfill => self.prepare_governance_backfill(store, now)?,
            Work::Contiguous => {
                use std::ops::Bound::{Excluded, Unbounded};
                let author = self
                    .sparse_contiguous_after
                    .and_then(|after| {
                        self.sparse_contiguous_pending
                            .range((Excluded(after), Unbounded))
                            .next()
                            .copied()
                    })
                    .or_else(|| self.sparse_contiguous_pending.first().copied());
                Native::Contiguous(author)
            }
            Work::ProviderPrune => {
                if self.role_owed.take_key_provider_prune() {
                    self.key_provider_prune_pending = true;
                    self.key_provider_prune_after = None;
                }
                if self
                    .key_provider_prune_wait
                    .as_ref()
                    .is_some_and(|wait| !wait.ready.load(std::sync::atomic::Ordering::Acquire))
                {
                    return Ok(None);
                }
                self.key_provider_prune_wait = None;
                let peer = if self.key_provider_prune_pending {
                    let wake = self.history_publication_wake();
                    let read = self.history_read(store)?;
                    if read.publication_busy() {
                        drop(read);
                        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let signal = Arc::clone(&ready);
                        let owed = Arc::clone(&self.role_owed);
                        let local = self.me();
                        let task = tokio::spawn(async move {
                            wake.await;
                            signal.store(true, std::sync::atomic::Ordering::Release);
                            owed.mark_key_provider_prune(local);
                        });
                        self.key_provider_prune_wait =
                            Some(sparse_history::KeyProviderPruneWait { ready, task });
                        return Ok(None);
                    }
                    read.key_provider_cursor_after(self.key_provider_prune_after)?
                } else {
                    None
                };
                Native::Provider {
                    forget: peer.is_some_and(|peer| !self.is_member(&peer)),
                    peer,
                }
            }
            Work::Legacy => Native::Legacy {
                context: Box::new(self.legacy_projection_context(store)?),
                was_pending: self.legacy_classification_pending(store)?,
            },
            Work::CleanupProvisional { owner } => Native::CleanupProvisional(owner),
            Work::StartupCleanup => Native::StartupCleanup(self.legacy_preparation),
            Work::AdminRemoval { member, after } => {
                if self.me() != self.genesis.creator_pubkey().fingerprint() {
                    return Err(Error::Profile(
                        "only the room's creator may add or remove an admin",
                    ));
                }
                let page = self
                    .current_governance(store)?
                    .certificates(&member, after, 1)?;
                let certificate = page.rows.first().copied();
                let append = if certificate.is_some() {
                    Some(Box::new(self.prepare_pending_control(
                        store,
                        Arc::clone(&owner),
                        now,
                    )?))
                } else {
                    None
                };
                Native::Admin {
                    append,
                    certificate,
                    next: page.next,
                    count: page.rows.len(),
                }
            }
        };
        let has_append = matches!(
            &native,
            Native::Admin {
                append: Some(_),
                ..
            }
        );
        let pin = if has_append {
            None
        } else {
            Some(self.reserve_pending_write(store, Arc::clone(&owner))?)
        };
        Ok(Some(Prepared {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            me: self.me(),
            now,
            sek: self.sek.reader(),
            index: self.entries.fork_reader(),
            native,
            pin,
        }))
    }

    pub(crate) fn finish_pending_governance_work(
        &mut self,
        store: &Store,
        mut completed: Completed,
    ) -> Result<Saved> {
        if !completed.can_install(self, &completed.pending.owner) {
            return completed.into_result();
        }
        if completed.committed {
            self.entries.committed();
        }
        if matches!(
            &completed.pending.native,
            Native::StartupCleanup(_) | Native::CleanupProvisional(_)
        ) {
            // Cancellation detaches its reader even when a later native cleanup write fails.
            // Preserve those exact scalar visibility effects, never the worker's page cache.
            self.entries
                .copy_reader_visibility(&completed.pending.index);
        }
        if let Native::Backfill {
            projection,
            after,
            refreshing,
            observe_now,
            ..
        } = &mut completed.pending.native
        {
            if *observe_now {
                self.now_hint = self.now_hint.max(completed.pending.now.get());
            }
            if completed.committed {
                if let Some(projection) = projection.take() {
                    if let Err(error) = projection.install(self, store) {
                        completed.result = Err(error);
                    }
                }
                self.chains_advanced = false;
            }
            if completed.result.is_ok() {
                self.backfill_after = *after;
                self.backfill_refreshing = *refreshing;
            }
        }
        match completed.delta {
            Delta::Contiguous { author, progress } => {
                if let Some(state) = progress.state {
                    let was_member = self.is_member(&author);
                    if let Err(error) = self.dag.restore_contiguous_author(author, &state) {
                        completed.result = Err(error);
                    } else {
                        if !was_member && self.is_member(&author) {
                            self.key_member_became_current(author);
                        }
                        self.role_cuts.insert(author, state.seq);
                        self.note_role_progress(author, state.seq);
                    }
                }
                if progress.more {
                    self.sparse_contiguous_pending.insert(author);
                } else {
                    self.sparse_contiguous_pending.remove(&author);
                }
            }
            Delta::Startup(preparation) => {
                self.legacy_preparation = preparation;
            }
            Delta::CleanupProvisional { complete } => {
                if complete {
                    self.schedule_legacy_startup_cleanup();
                }
            }
            Delta::Admin(append) => {
                if let Err(error) = self.finish_pending_text(store, *append) {
                    completed.result = Err(error);
                }
            }
            Delta::None => {}
        }
        if completed.result.is_ok() {
            match &completed.pending.native {
                Native::Contiguous(author) => {
                    self.sparse_contiguous_after = *author;
                    completed.result = Ok(Saved::Contiguous {
                        pending: !self.sparse_contiguous_pending.is_empty(),
                    });
                }
                Native::Provider { peer, .. } => {
                    self.key_provider_prune_after = *peer;
                    if peer.is_none() {
                        self.key_provider_prune_pending = false;
                    }
                }
                _ => {}
            }
        }
        if let Native::Legacy { context, .. } = &completed.pending.native {
            self.install_legacy_projection_context(context);
        }
        self.release_pending_text(&completed.pending.owner, false);
        if let Err(error) = &completed.result {
            if !matches!(
                &completed.pending.native,
                Native::StartupCleanup(_) | Native::CleanupProvisional(_)
            ) && !ChannelState::legacy_classification_refreshing(error)
            {
                self.poison(error);
            }
        }
        completed.result
    }

    /// Preserve the original sweep's cheap early return before backfill/pruning. This changes
    /// only its observation watermark; all saved-history changes stay on the native worker.
    pub(crate) fn retention_turn_ready(
        &mut self,
        store: &Store,
        now: crate::time::Ms,
    ) -> Result<bool> {
        self.now_hint = self.now_hint.max(now.get());
        if self.legacy_cache_only(store)? {
            return Ok(false);
        }
        match self.require_governance_ready(store, now) {
            Ok(_) => Ok(self.governance_display_current(now.get())),
            Err(error) if governance::refreshing(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn retention_projection_current(&self) -> bool {
        !self.projection_state.pending
            && self.projection_state.policy
                == Some([
                    self.effective_retention(),
                    self.effective_step_retention(),
                    self.legacy_sessions.display_revision(),
                ])
    }

    fn prepare_governance_backfill(&self, store: &Store, now: crate::time::Ms) -> Result<Native> {
        let view = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        let mut after = self.backfill_after;
        let mut edits = BTreeMap::new();
        let mut rows = Vec::new();
        let cache_only = self.legacy_cache_only(store)?;
        if cache_only || !view.has_backfill() {
            return Ok(Native::Backfill {
                projection: None,
                rows,
                edits,
                after: if cache_only {
                    self.backfill_after
                } else {
                    None
                },
                refreshing: cache_only && self.backfill_refreshing,
                active: false,
                observe_now: !cache_only,
            });
        }
        let mut projection = SemanticProjection::new(self, store, now.get())?;
        let consent = match self.consent_facts() {
            Ok(facts) => Some(facts),
            Err(error) if governance::refreshing(&error) => None,
            Err(error) => return Err(error),
        };
        #[cfg(feature = "test-knobs")]
        let held = self.render_backfill_held_for_proof();
        #[cfg(not(feature = "test-knobs"))]
        let held = false;
        if let Some(consent) = consent.as_ref().filter(|_| !held) {
            let read = view.read_index();
            let sparse = read.sparse_enabled();
            let mut bytes = 0usize;
            for _ in 0..RENDER_BACKFILL_ROWS_PER_TURN {
                let Some((author, seq)) = next_backfill(&view, after, &edits)? else {
                    after = None;
                    break;
                };
                after = Some(author);
                if author != self.me()
                    && !(consent.can_read(&self.me(), &author) && self.has_sender_key(&author))
                {
                    edits.insert(author, None);
                    continue;
                }
                let (entry_seq, entry) = if sparse {
                    let Some(selected) = read.next_sparse_backfill(&author, seq)? else {
                        edits.insert(author, None);
                        continue;
                    };
                    selected
                } else {
                    let head = self.dag.verified_head(&author);
                    if seq > head {
                        edits.insert(author, None);
                        continue;
                    }
                    (
                        seq,
                        Some(
                            read.get(&author, seq)?
                                .ok_or(Error::MalformedAtRest("backfill entry missing"))?,
                        ),
                    )
                };
                let cost = entry
                    .as_ref()
                    .and_then(|entry| entry.payload.as_ref())
                    .map_or(0, Vec::len);
                if bytes != 0 && bytes.saturating_add(cost) > 1024 * 1024 {
                    break;
                }
                let next = if !sparse && entry_seq == self.dag.verified_head(&author) {
                    None
                } else {
                    Some(
                        entry_seq
                            .checked_add(1)
                            .ok_or(Error::MalformedAtRest("backfill sequence exhausted"))?,
                    )
                };
                edits.insert(author, next);
                let Some(entry) = entry else { continue };
                bytes = bytes.saturating_add(cost);
                let hash = entry.entry_hash();
                if view.fact(&hash)?.is_some()
                    || read.read_receipt_cache(&hash)?.is_some()
                    || read
                        .retention(&hash)?
                        .is_some_and(|tracked| tracked.cache_id.is_some())
                    || self.private_id(store, &hash)?.is_some()
                    || self
                        .drive
                        .pending
                        .iter()
                        .any(|(row, _)| row.entry_hash == hash)
                {
                    continue;
                }
                let Some(payload) = entry.payload.as_deref() else {
                    continue;
                };
                if !matches!(classify_payload(payload), Ok(EntryKind::Content)) {
                    continue;
                }
                let prepared = projection.prepare(self, store, author, hash, payload, true)?;
                rows.push((entry, prepared));
            }
        }
        projection.seal_preparation(self)?;
        Ok(Native::Backfill {
            projection: Some(Box::new(projection)),
            rows,
            edits,
            after,
            refreshing: if held {
                self.backfill_refreshing
            } else {
                consent.is_none()
            },
            active: true,
            observe_now: true,
        })
    }
}

impl Prepared {
    pub(crate) fn run(mut self, store: &Store, signer: &dyn RootSigner) -> Completed {
        let mut delta = Delta::None;
        let mut committed = false;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let index = &self.index;
            match &mut self.native {
                Native::Backfill {
                    projection,
                    rows,
                    edits,
                    refreshing,
                    active,
                    ..
                } => self.sek.with(|sek| {
                    if !*active {
                        return Ok(Saved::Backfill {
                            rendered: 0,
                            pending: false,
                            session_rendered: 0,
                            placed: false,
                        });
                    }
                    let projection = projection
                        .as_mut()
                        .ok_or(Error::Profile("backfill projection owner missing"))?;
                    let mut batch = store.batch()?;
                    batch.derived();
                    {
                        let mut writer = index.write(&mut batch, sek, &self.room)?;
                        for (author, next) in edits {
                            writer.queue_backfill(*author, *next)?;
                        }
                        writer.seal()?;
                    }
                    for (entry, prepared) in std::mem::take(rows) {
                        projection.apply_with(&mut batch, sek, prepared, &entry)?;
                    }
                    if projection.receivers_advanced() {
                        projection.queue_receivers_with(&mut batch, sek)?;
                    }
                    batch.commit()?;
                    committed = true;
                    #[cfg(feature = "test-knobs")]
                    engage_render_hold(&self.room, &projection.rows);
                    let rendered = projection.rows.len();
                    let session_rendered = projection
                        .sessions
                        .iter()
                        .filter(|(row, _)| !crate::node::drive::is_key_changed(&row.session_id))
                        .count();
                    projection.after_commit_with(store, sek)?;
                    let pending =
                        *refreshing || index.render_view(store, sek, &self.room)?.has_backfill();
                    Ok(Saved::Backfill {
                        rendered,
                        pending,
                        session_rendered,
                        placed: true,
                    })
                }),
                Native::Contiguous(None) => Ok(Saved::Contiguous { pending: false }),
                Native::Contiguous(Some(author)) => self.sek.with(|sek| {
                    let mut batch = store.batch()?;
                    batch.derived();
                    let mut writer = index.write(&mut batch, sek, &self.room)?;
                    let progress = writer.advance_sparse_contiguous(author, &self.me)?;
                    if progress.state.is_some() || progress.more {
                        writer.seal()?;
                        batch.commit()?;
                        committed = true;
                    }
                    let pending = progress.more;
                    delta = Delta::Contiguous {
                        author: *author,
                        progress,
                    };
                    Ok(Saved::Contiguous { pending })
                }),
                Native::Provider { peer, forget } => self.sek.with(|sek| {
                    if let Some(peer) = peer.filter(|_| *forget) {
                        let mut batch = store.batch()?;
                        batch.derived();
                        let mut writer = index.write(&mut batch, sek, &self.room)?;
                        writer.forget_key_provider_cursor(peer)?;
                        writer.seal()?;
                        batch.commit()?;
                        committed = true;
                    }
                    Ok(Saved::ProviderPrune {
                        pending: peer.is_some(),
                    })
                }),
                Native::Legacy {
                    context,
                    was_pending,
                } => self.sek.with(|sek| {
                    let pending = context.advance(store, sek, self.now.get())?;
                    committed = true;
                    Ok(Saved::Legacy {
                        advanced: *was_pending && !pending,
                        pending,
                    })
                }),
                Native::CleanupProvisional(owner) => self.sek.with(|sek| {
                    let complete =
                        index.cleanup_legacy_provisional(store, sek, &self.room, *owner)?;
                    committed = true;
                    delta = Delta::CleanupProvisional { complete };
                    Ok(Saved::CleanupProvisional {
                        owner: *owner,
                        complete,
                    })
                }),
                Native::StartupCleanup(previous) => self.sek.with(|sek| {
                    if *previous == entry_store::Preparation::Ready {
                        return Ok(Saved::StartupCleanup {
                            blocks_current: false,
                        });
                    }
                    let preparation = index.cleanup_orphan_provisional(store, sek, &self.room)?;
                    let blocks_current = preparation == entry_store::Preparation::CleanupPending;
                    delta = Delta::Startup(preparation);
                    committed = true;
                    Ok(Saved::StartupCleanup { blocks_current })
                }),
                Native::Admin {
                    append,
                    certificate,
                    next,
                    count,
                } => {
                    if let (Some(append), Some(certificate)) = (append.take(), certificate.take()) {
                        let payload = crate::governance::cert::AdminRevocation::build(
                            signer,
                            &self.room,
                            self.epoch,
                            certificate,
                            crate::governance::cert::RevocationReason::NoLongerNeeded,
                        )?
                        .to_wire();
                        let completed = append.run_governance(store, signer, payload);
                        delta = Delta::Admin(Box::new(completed));
                    }
                    Ok(Saved::AdminRemoval {
                        count: *count,
                        next: *next,
                    })
                }
            }
        }))
        .unwrap_or_else(|_| Err(Error::Profile("governance save worker stopped")));
        Completed {
            pending: self,
            delta,
            committed,
            result,
        }
    }
}

impl Completed {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.pending.room == channel.channel_id
            && self.pending.epoch == channel.epoch
            && Arc::ptr_eq(&self.pending.owner, owner)
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        match &mut self.delta {
            Delta::Admin(append) => append.take_history_pin(),
            _ => self.pending.pin.take(),
        }
    }
    pub(crate) fn into_result(self) -> Result<Saved> {
        if let Delta::Admin(append) = self.delta {
            append.result?;
        }
        self.result
    }
}

/// Overlay only cursor edits from this bounded quantum on the immutable committed tree.
/// Removed authors are skipped without spending another row or resetting the fair cursor.
fn next_backfill(
    view: &entry_store::RenderView<'_>,
    after: Option<Digest32>,
    edits: &BTreeMap<Digest32, Option<u64>>,
) -> Result<Option<(Digest32, u64)>> {
    let mut scan = after;
    let mut wrapped = false;
    loop {
        let Some((author, saved)) = view.next_backfill_after(scan)? else {
            if !wrapped && after.is_some() {
                scan = None;
                wrapped = true;
                continue;
            }
            return Ok(None);
        };
        if wrapped && after.is_some_and(|after| author > after) {
            return Ok(None);
        }
        match edits.get(&author) {
            Some(Some(seq)) => return Ok(Some((author, *seq))),
            Some(None) => scan = Some(author),
            None => return Ok(Some((author, saved))),
        }
    }
}
