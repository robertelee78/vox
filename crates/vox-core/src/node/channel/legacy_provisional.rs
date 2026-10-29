//! Explicit legacy-history staging ownership. These calls do not schedule network work or
//! confer acceptance. The caller owns current authorization, budgets and the local request.

use super::*;

pub(crate) const LEGACY_HISTORY_REQUIRED: &str = super::UNSUPPORTED_ROOM_FORMAT;
pub(crate) use entry_store::{LegacyProvisionalOwner, LegacyProvisionalState, LegacyRequired};

impl ChannelState {
    /// Accepted history stays readable while a legacy gap or its exact publication is
    /// paused. The missing prefix can contain control, so it cannot authorize current work.
    /// This is a read-only check; it never resumes publication or network traffic.
    pub(crate) fn legacy_cache_only(&self, store: &Store) -> Result<bool> {
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        Ok(!read.sparse_enabled()
            && (read.legacy_provisional().is_some() || read.legacy_required_any()))
    }

    pub(crate) fn require_legacy_current(&self, store: &Store) -> Result<()> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if self.legacy_cache_only(store)? {
            return Err(Error::Profile(LEGACY_HISTORY_REQUIRED));
        }
        Ok(())
    }
    pub(crate) fn legacy_startup_cleanup_pending(&self) -> bool {
        self.legacy_preparation != entry_store::Preparation::Ready
    }

    pub(crate) fn legacy_startup_cleanup_blocks_current(&self) -> bool {
        self.legacy_preparation == entry_store::Preparation::CleanupPending
    }

    pub(crate) fn schedule_legacy_startup_cleanup(&mut self) {
        if self.legacy_preparation == entry_store::Preparation::Ready {
            self.legacy_preparation = entry_store::Preparation::ReadyWithCleanup;
        }
    }

    /// Record only the exact authenticated current v1 header, never its body or peer HAVE.
    pub(crate) fn note_legacy_required(&self, store: &Store, tip: &Entry) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let sk = &tip.skeleton;
        if sk.v2.is_some()
            || !tip.is_signed()
            || tip.payload.is_some()
            || sk.channel_id != self.channel_id
            || sk.epoch != self.epoch
            || !self
                .admission
                .is_admitted(&self.channel_id, self.epoch, &sk.author_id)
        {
            return Err(Error::StreamRefused(
                "legacy tip room, epoch or author differs",
            ));
        }
        let key = self
            .authors
            .get(&sk.author_id)
            .ok_or(Error::StreamRefused("legacy tip author unknown"))?;
        tip.verify(key)?;
        // An unsigned attached suffix is never evidence of an accepted end. The writer
        // checks the sealed accepted restart feed; these are the DAG's actual refusals.
        if self
            .dag
            .refused_from(&sk.author_id)
            .is_some_and(|from| sk.seq >= from)
            || (self.dag.is_frozen(&sk.author_id) && sk.seq > self.dag.verified_head(&sk.author_id))
        {
            return Err(Error::StreamRefused(
                "legacy tip extends refused or frozen feed",
            ));
        }
        let required = LegacyRequired {
            author: sk.author_id,
            through: sk.seq,
            hash: tip.entry_hash(),
        };
        let mut batch = store.batch()?;
        // This authenticated requirement is a re-fetchable restart index, not a user fact.
        batch.derived();
        let mut writer = self
            .entries
            .write(&mut batch, &self.sek, &self.channel_id)?;
        let changed = writer.note_legacy_required(required)?;
        if changed {
            writer.seal()?;
            batch.commit()?;
            self.entries.committed();
        }
        Ok(changed)
    }
    pub(crate) fn legacy_provisional_state(
        &self,
        store: &Store,
    ) -> Result<Option<LegacyProvisionalState>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        Ok(self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .legacy_provisional())
    }
}
