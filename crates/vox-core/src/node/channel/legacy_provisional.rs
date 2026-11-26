//! Explicit legacy-history staging ownership. These calls do not schedule network work or
//! confer acceptance. The caller owns current authorization, budgets and the local request.

use super::*;

pub(crate) const LEGACY_HISTORY_REQUIRED: &str = super::UNSUPPORTED_ROOM_FORMAT;
pub(crate) use entry_store::{LegacyProvisionalOwner, LegacyProvisionalState};

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
        if self.poisoned.get() {
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

    pub(crate) fn legacy_provisional_state(
        &self,
        store: &Store,
    ) -> Result<Option<LegacyProvisionalState>> {
        if self.poisoned.get() {
            return Err(self.save_failure());
        }
        Ok(self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .legacy_provisional())
    }
}
