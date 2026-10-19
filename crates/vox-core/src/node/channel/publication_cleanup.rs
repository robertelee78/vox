//! Current-format guards and bounded cleanup after an interrupted publication.

use super::*;

impl ChannelState {
    pub(crate) fn require_supported_format(&self, store: &Store) -> Result<()> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.entries
            .require_current_format(store, &self.sek, &self.channel_id)
    }
    pub(crate) fn publication_cleanup_pending(&self) -> bool {
        self.publication_preparation != entry_store::Preparation::Ready
    }

    pub(crate) fn publication_cleanup_blocks_current(&self) -> bool {
        self.publication_preparation == entry_store::Preparation::CleanupPending
    }

    /// Advance one local startup-cleanup quantum. `true` means accepted current room state is
    /// usable; detached retired roots may still require later background turns.
    pub(crate) fn advance_publication_cleanup(&mut self, store: &Store) -> Result<bool> {
        if self.publication_preparation == entry_store::Preparation::Ready {
            return Ok(true);
        }
        self.publication_preparation = self.cleanup_orphan_publication(store)?;
        Ok(self.publication_preparation != entry_store::Preparation::CleanupPending)
    }

    pub(crate) fn cleanup_orphan_publication(
        &self,
        store: &Store,
    ) -> Result<entry_store::Preparation> {
        self.entries
            .cleanup_orphan_provisional(store, &self.sek, &self.channel_id)
    }
}
