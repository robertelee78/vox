//! Public, root-authenticated Session history floors (ADR-031 SA-8).
//!
//! This is an explicit control subtype of the existing group-content carrier. Its nine-field
//! body is not a three-field encrypted GroupMessage. Published readers classify the carrier as
//! content, keep the signed entry, and skip its unknown body without interrupting room sync.
//! The enclosing Entry's root signature authenticates every field; no sender key is disclosed.

use super::session_projection::floor_index;
use super::*;

const MARKER: &str = "vox/session-floor/v1";

pub(super) struct Floor {
    pub(super) room: Digest32,
    pub(super) author: Digest32,
    pub(super) recipient: Digest32,
    pub(super) epoch: u64,
    pub(super) generation: u64,
    pub(super) iteration: u64,
    pub(super) first_seq: u64,
    pub(super) membership: u64,
}

impl Floor {
    pub(super) fn wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(9)
            .text(MARKER)
            .bytes(&self.room)
            .bytes(&self.author)
            .bytes(&self.recipient)
            .uint(self.epoch)
            .uint(self.generation)
            .uint(self.iteration)
            .uint(self.first_seq)
            .uint(self.membership);
        let mut out = GROUP_MSG_SIGN_DOMAIN.as_bytes().to_vec();
        out.extend(e.finish());
        out
    }

    pub(super) fn read(payload: &[u8]) -> Option<Self> {
        let mut d = Decoder::new(payload.strip_prefix(GROUP_MSG_SIGN_DOMAIN.as_bytes())?);
        if d.array().ok()? != 9 || d.text().ok()? != MARKER {
            return None;
        }
        let f = Self {
            room: d.bytes().ok()?.try_into().ok()?,
            author: d.bytes().ok()?.try_into().ok()?,
            recipient: d.bytes().ok()?.try_into().ok()?,
            epoch: d.uint().ok()?,
            generation: d.uint().ok()?,
            iteration: d.uint().ok()?,
            first_seq: d.uint().ok()?,
            membership: d.uint().ok()?,
        };
        d.finish().ok()?;
        (f.wire() == payload).then_some(f)
    }
}

/// Whether a payload is a canonical floor control record. Its enclosing verified log entry
/// supplies authentication. Retention must preserve these controls, as it does checkpoints.
pub(crate) fn is_session_floor(payload: &[u8]) -> bool {
    Floor::read(payload).is_some()
}

impl ChannelState {
    pub(crate) fn authorization_refreshing(error: &Error) -> bool {
        floor_index::refreshing(error)
            || matches!(
                error,
                Error::StreamRefused(super::private_session::CONTROL_REFRESHING)
            )
    }

    pub(super) fn floor_author(
        &self,
        transaction: Transaction<'_, '_>,
        author: &Digest32,
    ) -> Result<floor_index::Author> {
        floor_index::author(transaction, &self.sek, &self.channel_id, author)
    }

    pub(super) fn index_session_floors(&self, store: &Store) -> Result<()> {
        if !self.current_session_controls_ready(store)? {
            return Err(Error::StreamRefused(floor_index::REFRESHING));
        }
        Ok(())
    }
}
