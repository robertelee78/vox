//! One explicit legacy prefix quantum. Sealed staging is not accepted history; only the
//! existing signed-witness publication switches it into the room's authenticated roots.
use super::legacy_provisional::{LegacyProvisionalOwner, LegacyProvisionalState};
use super::*;

#[derive(Clone, Copy)]
pub(crate) struct LegacySync {
    pub owner: LegacyProvisionalOwner,
    pub through: u64,
    pub node: Digest32,
    pub epoch: u64,
    pub grant: Digest32,
}
impl LegacySync {
    pub(super) fn check(&self, room: &ChannelState, store: &Store) -> Result<()> {
        if room.epoch != self.epoch
            || room.history_instance(store)? != self.owner.instance
            || crate::node::history_stream::authorization_generation(
                store,
                self.node,
                room.channel_id,
                self.owner.instance,
                self.epoch,
            )? != self.grant
        {
            return Err(Error::Profile(
                "Legacy history authorization changed; resume explicitly",
            ));
        }
        Ok(())
    }
    pub(super) fn check_in(&self, room: &ChannelState, batch: &Batch<'_>) -> Result<()> {
        if crate::node::history_stream::authorization_generation_in(
            batch,
            self.node,
            room.channel_id,
            self.owner.instance,
            self.epoch,
        )? != self.grant
        {
            return Err(Error::Profile(
                "Legacy history authorization changed; resume explicitly",
            ));
        }
        Ok(())
    }
}

impl ChannelState {
    pub(crate) fn legacy_accepted_head(&self, author: &Digest32) -> u64 {
        self.dag.verified_head(author)
    }
    fn attach_legacy_feed(&mut self, state: LegacyProvisionalState) -> Result<()> {
        self.dag.restore_legacy_provisional(
            state.owner.author,
            state.base_seq,
            state.base_hash,
            state.tail_seq,
            state.tail_hash,
            state.first_claimed_ms,
            state.ended,
        )
    }
    pub(crate) fn finish_legacy_sync(&mut self, store: &Store, request: LegacySync) -> Result<()> {
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        let restart = read.restart_state().ok_or(Error::MalformedAtRest(
            "legacy accepted restart state missing",
        ))?;
        let accepted = match restart.feeds.get(&request.owner.author) {
            Some(accepted) => accepted.clone(),
            None if read.legacy_provisional().is_some_and(|state| {
                state.owner == request.owner
                    && state.base_seq == 0
                    && state.base_hash == ZERO_HASH
                    && (self.dag.verified_head(&request.owner.author) == 0
                        || (state.pending_witness != 0
                            && state.pending_witness == state.tail_seq
                            && self.dag.feed(&request.owner.author).is_some_and(|feed| {
                                feed.max_seq() == state.tail_seq
                                    && feed.head_hash() == state.tail_hash
                            })))
            }) =>
            {
                Default::default()
            }
            None => return Err(Error::MalformedAtRest("legacy accepted author missing")),
        };
        drop(read);
        self.dag
            .restore_legacy_accepted(request.owner.author, &accepted)?;
        self.detach_legacy_provisional(request.owner)
    }

    /// Returns a completed local quantum, or None when one network exchange may follow.
    /// The caller holds its charged whole-record envelope and calls finish_legacy_sync on
    /// every exit. No loop walks an old unsigned prefix here.
    pub(crate) fn prepare_legacy_sync(
        &mut self,
        store: &Store,
        request: LegacySync,
        now: crate::time::Ms,
    ) -> Result<Option<SyncOutcome>> {
        request.check(self, store)?;
        let ended_before_target = self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .restart_state()
            .and_then(|state| state.feeds.get(&request.owner.author))
            .is_some_and(|feed| feed.ended && feed.seq < request.through);
        if ended_before_target {
            return Ok(Some(SyncOutcome {
                legacy_invalid: true,
                ..SyncOutcome::default()
            }));
        }
        if self
            .legacy_provisional_state(store)?
            .is_some_and(|state| state.owner == request.owner)
        {
            // A cancelled transport may have lost its final room-lock race. Restore the
            // exact published feed before reattaching this request's compact tail.
            self.finish_legacy_sync(store, request)?;
        }
        let state = self.bind_legacy_provisional(store, request.owner)?;
        self.attach_legacy_feed(state)?;
        let progress = self.legacy_publication_progress(store, request.owner)?;
        if state.pending_witness == 0 && progress.is_none() {
            return Ok(None);
        }
        let mut out = SyncOutcome {
            legacy_next: Some(state.tail_seq.saturating_add(1)),
            legacy_pending: true,
            ..SyncOutcome::default()
        };
        if let Some(progress) = progress {
            if progress.switched {
                out.legacy_pending = !self.cleanup_legacy_witness(store, request.owner)?;
            } else if self.advance_legacy_witness(store, request.owner)? {
                let entry = self
                    .entries
                    .read(store, &self.sek, &self.channel_id)?
                    .get(&request.owner.author, progress.through)?
                    .ok_or(Error::MalformedAtRest("legacy witness missing"))?;
                let key = self
                    .resolver()
                    .key_for(&request.owner.author)
                    .ok_or(Error::Profile(
                        "Legacy witness author is no longer admitted",
                    ))?;
                entry.verify(&key)?;
                // This exact witness was already linked when staged, and the bounded
                // promotion has now built all prefix facts. The final effects transaction
                // atomically switches those roots, exactly as ordinary sync does.
                self.dag.detach_legacy_provisional(
                    request.owner.author,
                    progress.through,
                    entry.entry_hash(),
                    state.first_claimed_ms,
                    entry.skeleton.end_of_feed,
                )?;
                self.next_log_id = progress.after_log;
                self.projection_state.owed_range(
                    request.owner.author,
                    progress.from,
                    progress.through,
                );
                let count = progress.through - progress.from + 1;
                let witness_log = progress.after_log - 1;
                let invalid_extension =
                    entry.skeleton.end_of_feed && progress.through < request.through;
                let got = self.absorb_batch_authorized(
                    store,
                    vec![(
                        request.owner.author,
                        entry.entry_hash(),
                        entry.payload,
                        Some(witness_log),
                    )],
                    now.get(),
                    Some(count),
                    Some(request),
                )?;
                out.applied = got.applied;
                out.rendered = got.rendered;
                out.governance = got.governance;
                out.refused = got.refused;
                out.legacy_invalid = invalid_extension;
                out.legacy_pending = self
                    .legacy_publication_progress(store, request.owner)?
                    .is_some();
            }
        } else {
            // A crash may follow signed staging but precede creation of the publication
            // cursor. Reverify only this exact retained witness before beginning it.
            let entry = self
                .entries
                .read(store, &self.sek, &self.channel_id)?
                .get(&request.owner.author, state.pending_witness)?
                .ok_or(Error::MalformedAtRest("legacy pending witness missing"))?;
            let key = self
                .resolver()
                .key_for(&request.owner.author)
                .ok_or(Error::Profile(
                    "Legacy witness author is no longer admitted",
                ))?;
            entry.verify(&key)?;
            self.begin_legacy_witness(store, request.owner, &entry, self.next_log_id, now.get())?;
        }
        Ok(Some(out))
    }
}
