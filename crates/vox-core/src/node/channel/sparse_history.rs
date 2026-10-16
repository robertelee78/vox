//! Bounded access to authenticated-history state. Callers acquire the shared worker/buffer
//! envelope before these methods; every pinned store read is dropped before network I/O.

use super::*;
use crate::log::history::{
    ControlContext, Descriptor, LogScope, SignedHead, TreeBinding, MAX_CHUNK_BYTES,
};

/// Exact signed header and the length bound governing payload continuations.
pub(crate) struct HistoryHeader {
    pub wire: Vec<u8>,
    pub payload_len: u64,
}

/// A missing local body is not an authenticated expiry claim.
pub(crate) enum HistoryPayload {
    Missing,
    BodyNotHeld { payload_len: u64 },
    Chunk { payload_len: u64, bytes: Vec<u8> },
}

impl ChannelState {
    fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let read = self.entries.read(store, &self.sek, &self.channel_id)?;
        if !read.sparse_enabled() {
            return Err(Error::MalformedGovernance(
                "room has no activated authenticated-history format",
            ));
        }
        Ok(read)
    }

    /// The latest consistency-accepted commitment. It is not a control-ready or contiguous
    /// position, and serving it does not change either state.
    pub(crate) fn history_head(
        &self,
        store: &Store,
        author: &Digest32,
    ) -> Result<Option<SignedHead>> {
        let read = self.history_read(store)?;
        let Some(id) = read
            .sparse_author(author, LogScope::Public)?
            .and_then(|state| state.committed)
        else {
            return Ok(None);
        };
        read.history_head(&id)
    }

    pub(crate) fn history_context(
        &self,
        store: &Store,
        hash: &Digest32,
    ) -> Result<Option<ControlContext>> {
        self.history_read(store)?.history_context(hash)
    }

    pub(crate) fn history_header(
        &self,
        store: &Store,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<HistoryHeader>> {
        self.history_read(store)?
            .history_position_header(author, seq)?
            .map(|entry| {
                Ok(HistoryHeader {
                    wire: entry.header_wire(),
                    payload_len: entry.skeleton.payload_len,
                })
            })
            .transpose()
    }

    pub(crate) fn history_tree_range(
        &self,
        store: &Store,
        binding: TreeBinding,
        start: u64,
        leaves: u64,
    ) -> Result<Option<Descriptor>> {
        self.history_read(store)?
            .history_range(binding, start, leaves)
    }

    /// Whole-record AEAD still needs the caller's acquired large-record envelope. Only one
    /// requested chunk escapes this scope; no ciphertext/plaintext snapshot survives it.
    pub(crate) fn history_payload_chunk(
        &self,
        store: &Store,
        hash: &Digest32,
        offset: u64,
        limit: usize,
    ) -> Result<HistoryPayload> {
        if limit == 0 || limit > MAX_CHUNK_BYTES {
            return Err(Error::SizeLimitExceeded("history chunk limit"));
        }
        let read = self.history_read(store)?;
        let Some(entry) = read.history_entry(hash)? else {
            return Ok(HistoryPayload::Missing);
        };
        if entry.skeleton.v2.is_none() {
            return Err(Error::MalformedAtRest("legacy entry in activated history"));
        }
        let payload_len = entry.skeleton.payload_len;
        if offset > payload_len {
            return Err(Error::MalformedBundle(
                "history chunk offset beyond payload",
            ));
        }
        let Some(payload) = entry.payload else {
            return Ok(HistoryPayload::BodyNotHeld { payload_len });
        };
        if payload.len() as u64 != payload_len || sha256(&payload) != entry.skeleton.payload_hash {
            return Err(Error::MalformedAtRest(
                "stored history payload differs from header",
            ));
        }
        let start = usize::try_from(offset)
            .map_err(|_| Error::SizeLimitExceeded("history payload offset"))?;
        let end = start.saturating_add(limit).min(payload.len());
        Ok(HistoryPayload::Chunk {
            payload_len,
            bytes: payload[start..end].to_vec(),
        })
    }
}
