//! Explicit legacy-history staging ownership. These calls do not schedule network work or
//! confer acceptance. The caller owns current authorization, budgets and the local request.

use super::*;

pub(crate) const LEGACY_HISTORY_REQUIRED: &str =
    "Legacy history required; cached accepted messages are available; Resume or Cancel recovery";
pub(crate) use entry_store::{
    LegacyProvisionalOwner, LegacyProvisionalState, LegacyPublicationProgress, LegacyRequired,
};

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

    /// Advance one local startup-cleanup quantum. `true` means accepted current room state is
    /// usable; detached retired roots may still require later background turns.
    pub(crate) fn advance_legacy_startup_cleanup(&mut self, store: &Store) -> Result<bool> {
        if self.legacy_preparation == entry_store::Preparation::Ready {
            return Ok(true);
        }
        self.legacy_preparation = self.cleanup_legacy_orphan(store)?;
        Ok(self.legacy_preparation != entry_store::Preparation::CleanupPending)
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
    pub(crate) fn legacy_required(
        &self,
        store: &Store,
        author: &Digest32,
    ) -> Result<Option<LegacyRequired>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        Ok(self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .legacy_required(author))
    }
    pub(crate) fn legacy_required_any(&self, store: &Store) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        Ok(self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .legacy_required_any())
    }
    pub(crate) fn legacy_required_page(
        &self,
        store: &Store,
        after: Option<Digest32>,
        limit: usize,
    ) -> Result<Vec<LegacyRequired>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        Ok(self
            .entries
            .read(store, &self.sek, &self.channel_id)?
            .legacy_required_page(after, limit))
    }
    /// Background maintenance only advances a previously identified orphan, never a paused
    /// owner's publication. Schedule another bounded local turn for CleanupPending or
    /// ReadyWithCleanup; the latter permits current staging/reads immediately.
    pub(crate) fn cleanup_legacy_orphan(&self, store: &Store) -> Result<entry_store::Preparation> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.entries
            .cleanup_orphan_provisional(store, &self.sek, &self.channel_id)
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
    /// True means the exact owner no longer occupies current staging. Retired ciphertext
    /// can remain; call cleanup_legacy_orphan in later local maintenance turns to reclaim it.
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
