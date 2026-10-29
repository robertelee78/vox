//! Departure uses the authored control kernel; only its matching owner installs the receipt.
use super::*;

pub(crate) enum Prepared {
    Append(Box<PendingText>),
    Unchanged(Unchanged),
}

pub(crate) struct Unchanged {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    pin: Option<history::PendingHistoryRead>,
}

pub(crate) enum Saved {
    Installed(Departure),
    Detached,
}

pub(crate) struct Departure {
    pub(crate) generation: u64,
    pub(crate) alone: bool,
    pub(crate) epoch: u64,
}

pub(crate) enum Completed {
    Append(Box<CompletedText>),
    Unchanged(Unchanged),
}

impl ChannelState {
    pub(crate) fn prepare_pending_leave(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
    ) -> Result<Option<Prepared>> {
        if self.said_left(&self.me()) {
            let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
            return Ok(Some(Prepared::Unchanged(Unchanged {
                owner,
                room: self.channel_id,
                epoch: self.epoch,
                pin: Some(pin),
            })));
        }
        self.require_legacy_current(store)?;
        self.ensure_local_append_available_mode(store, false, false)?;
        self.ensure_governance_append_eligible_by(store, &self.me(), false, false)?;
        let sparse = self.uses_sparse_history(store)?;
        let pending = self.prepare_pending_append(
            store,
            self.me(),
            owner,
            now.get(),
            now.get(),
            sparse,
            Vec::new(),
            None,
        )?;
        Ok(Some(Prepared::Append(Box::new(pending))))
    }
}

impl Prepared {
    pub(crate) fn run(self, store: &Store, signer: &dyn RootSigner) -> Completed {
        let mut pending = match self {
            Self::Unchanged(unchanged) => return Completed::Unchanged(unchanged),
            Self::Append(pending) => pending,
        };
        let result = (|| {
            let presence = crate::governance::presence::Presence::build(
                signer,
                &pending.room,
                pending.epoch,
                false,
                pending.sender.chain_id(),
            )?;
            let now = crate::time::Ms(pending.now_millis);
            pending
                .append_control_owned(
                    store,
                    signer,
                    presence.to_wire(),
                    EntryKind::Governance,
                    SignedEntryKind::Governance,
                    now,
                )
                .map(|hash| super::Saved::Governance(Some(hash)))
        })();
        Completed::Append(Box::new(pending.complete_control(result)))
    }
}

impl Completed {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        match self {
            Self::Append(completed) => {
                completed.can_install(channel, owner)
                    && completed.pending.as_ref().is_some_and(|pending| {
                        pending.room == channel.channel_id && pending.epoch == channel.epoch
                    })
            }
            Self::Unchanged(unchanged) => {
                Arc::ptr_eq(&unchanged.owner, owner)
                    && unchanged.room == channel.channel_id
                    && unchanged.epoch == channel.epoch
                    && channel
                        .pending_text
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, owner))
            }
        }
    }
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        match self {
            Self::Append(completed) => completed.take_history_pin(),
            Self::Unchanged(unchanged) => unchanged.pin.take(),
        }
    }
    pub(crate) fn into_result(self) -> Result<Saved> {
        let result = match self {
            Self::Append(completed) => completed.result.map(|_| ()),
            Self::Unchanged(_) => Ok(()),
        };
        result.map(|_| Saved::Detached)
    }
    pub(crate) fn finish(self, channel: &mut ChannelState, store: &Store) -> Result<Saved> {
        match self {
            Self::Append(completed) => {
                channel.finish_pending_text(store, *completed)?;
            }
            Self::Unchanged(unchanged) => channel.release_pending_text(&unchanged.owner, false),
        }
        Ok(Saved::Installed(Departure {
            generation: channel
                .generation()
                .load(std::sync::atomic::Ordering::Relaxed),
            alone: channel
                .members()
                .into_iter()
                .all(|member| member == channel.me()),
            epoch: channel.epoch,
        }))
    }
}
