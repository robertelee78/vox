//! Authored legacy namespace metadata uses the same native feed publication as controls.
use super::*;

impl PendingText {
    pub(crate) fn legacy_index_committed(&self) -> bool {
        self.encrypted_control_committed
    }

    pub(crate) fn append_legacy_index_owned(
        &mut self,
        store: &Store,
        signer: &dyn RootSigner,
        plaintext: &[u8],
        cursor: SealedSegment,
        now: crate::time::Ms,
    ) -> Result<Digest32> {
        // A failed encrypted candidate is terminal: common completion poisons the exact room
        // rather than restoring/reusing its previous ordinary sender iteration.
        let payload = self.sender.encrypt(plaintext)?.to_wire();
        self.encrypted_control = true;
        let result = self.append_control_owned_with(
            store,
            signer,
            payload,
            EntryKind::Content,
            SignedEntryKind::Content,
            now,
            &[(18, Some(cursor))],
        );
        self.encrypted_control = false;
        result
    }
}
