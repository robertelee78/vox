//! Explicit legacy-history staging ownership. These calls do not schedule network work or
//! confer acceptance. The caller owns current authorization, budgets and the local request.

use super::*;
pub(crate) use entry_store::{
    LegacyProvisionalOwner, LegacyProvisionalState, LegacyPublicationProgress,
};

impl ChannelState {
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
    pub(crate) fn bind_legacy_provisional(
        &self,
        store: &Store,
        owner: LegacyProvisionalOwner,
    ) -> Result<LegacyProvisionalState> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.entries
            .bind_legacy_provisional(store, &self.sek, &self.channel_id, owner)
    }
    pub(crate) fn attach_legacy_provisional(
        &self,
        store: &Store,
        owner: LegacyProvisionalOwner,
    ) -> Result<LegacyProvisionalState> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.entries
            .attach_legacy_provisional(store, &self.sek, &self.channel_id, owner)
    }
    pub(crate) fn detach_legacy_provisional(&self, owner: LegacyProvisionalOwner) -> Result<()> {
        self.entries.detach_legacy_provisional(owner)
    }
    pub(crate) fn cleanup_legacy_provisional(
        &self,
        store: &Store,
        owner: LegacyProvisionalOwner,
    ) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.entries
            .cleanup_legacy_provisional(store, &self.sek, &self.channel_id, owner)
    }
    pub(crate) fn legacy_provisional_slice(
        &self,
        store: &Store,
        owner: LegacyProvisionalOwner,
        after: Option<u64>,
        reverse: bool,
    ) -> Result<Vec<entry_store::Locator>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.entries
            .read(store, &self.sek, &self.channel_id)?
            .legacy_provisional_slice(owner, after, reverse)
    }
    pub(crate) fn legacy_publication_progress(
        &self,
        store: &Store,
        owner: LegacyProvisionalOwner,
    ) -> Result<Option<LegacyPublicationProgress>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.entries
            .read(store, &self.sek, &self.channel_id)?
            .legacy_publication(owner)
    }
    pub(crate) fn cleanup_legacy_witness(
        &self,
        store: &Store,
        owner: LegacyProvisionalOwner,
    ) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.entries
            .cleanup_legacy_publication(store, &self.sek, &self.channel_id, owner)
    }
    /// Caller verified the witness and feed linkage. This stores the existing publication
    /// cursor only; a later explicit Resume advances one copy/order quantum.
    pub(crate) fn begin_legacy_witness(
        &self,
        store: &Store,
        owner: LegacyProvisionalOwner,
        witness: &Entry,
        first_log: u64,
        received_ms: u64,
    ) -> Result<()> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let state = self
            .legacy_provisional_state(store)?
            .filter(|s| s.owner == owner)
            .ok_or(Error::MalformedAtRest("legacy witness owner changed"))?;
        self.entries.begin_legacy_publication(
            store,
            &self.sek,
            &self.channel_id,
            owner,
            entry_store::Publication {
                witness,
                from: state
                    .base_seq
                    .checked_add(1)
                    .ok_or(Error::MalformedAtRest("legacy base exhausted"))?,
                first_log,
                received_ms,
                bodyless_prefix: true,
                origin: self.genesis.body.created_ms,
            },
        )
    }
    pub(crate) fn advance_legacy_witness(
        &self,
        store: &Store,
        owner: LegacyProvisionalOwner,
    ) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.entries
            .advance_legacy_publication(store, &self.sek, &self.channel_id, owner)
    }
}
