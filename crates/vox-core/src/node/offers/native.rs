//! Compact original-command dismissal continuation; never holds room or actor ownership.
use super::*;

impl DismissedOffers {
    /// The same bounded algorithm used by the public borrowed-room wrapper.
    pub(super) fn dismiss_bases(
        &mut self,
        bases: impl IntoIterator<Item = (Digest32, OfferBasis)>,
    ) -> bool {
        let before = self.entries.len();
        self.entries.extend(bases);
        while self.entries.len() > MAX_DISMISSED {
            self.entries.pop_first();
        }
        self.entries.len() != before
    }

    pub(super) fn queue_save(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        signer: &dyn RootSigner,
    ) -> Result<()> {
        let sealed = seal_segment(
            &sek(signer)?,
            SegmentKind::Trust,
            SEGMENT_ID,
            &self.to_bytes(),
        )?;
        let mut blob = Vec::with_capacity(NONCE_LEN + sealed.ciphertext.len());
        blob.extend_from_slice(&sealed.nonce);
        blob.extend_from_slice(&sealed.ciphertext);
        batch.put_meta(META_KEY, &blob)
    }
}

/// Read latest global metadata AFTER writer admission, never replace it with a command-admission
/// snapshot. `None` preserves the original helper's exact length-based no-change semantics.
pub(crate) fn dismiss(
    store: &Store,
    signer: &dyn RootSigner,
    bases: Vec<(Digest32, OfferBasis)>,
) -> Result<Option<DismissedOffers>> {
    let mut batch = store.batch()?;
    let mut next = DismissedOffers::load(store, signer)?;
    if !next.dismiss_bases(bases) {
        return Ok(None);
    }
    next.queue_save(&mut batch, signer)?;
    batch.commit()?;
    Ok(Some(next))
}
