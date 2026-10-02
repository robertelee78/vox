//! **Removals from the ring that a closed room has not yet acted on** (V210-118, the amendment for
//! a removal while a room is closed).
//!
//! Removing a member from the keyring must change the lock in every room shared with it
//! (ADR-020 §3), and since V210-118 it also drops that member's keys, so nothing it posts
//! afterwards opens here. Both act on rooms that are open. A room a person closed in the TUI stays
//! closed across restarts, and its key is not held while it is closed, so neither could happen
//! there: after the reopen the removed member went on reading what this identity posts, and this
//! identity, having dropped nothing, went on reading the member. And once the room had dropped the
//! member's keys on opening, re-trusting the member never brought them back, because nothing new
//! was released to it.
//!
//! So the removal is recorded here for each closed room, and acted on when the room next opens:
//! the member's keys are dropped and the lock is changed (revoke and rotate), then the record is
//! cleared. A re-trust before the reopen clears it, since the decision it stood for is withdrawn.
//! Kept **beside the keyring**, sealed under an identity-derived key, so no room passphrase is
//! needed to write it.

use std::collections::BTreeSet;

use crate::atrest::sek::Sek;
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::RootSigner;
use crate::node::store::Store;
use crate::node::trust::MAX_TRUSTED;

/// HKDF label for the set's sealing key, taken over `self_seed` ([`crate::atrest::seal`]).
pub const PENDING_LOCK_SEK_INFO: &[u8] = b"vox/pending-lock-sek/v1";

/// The set's sealing key.
pub fn pending_lock_sek(signer: &dyn RootSigner) -> Result<Sek> {
    crate::atrest::seal::sek(signer, PENDING_LOCK_SEK_INFO)
}

/// The metadata key the sealed set is stored under.
pub const META_KEY: &str = "pending-lock";

/// Its slot within [`SegmentKind::Trust`]: the keyring is 0, the pending consents 1, the consent
/// order 3.
pub const SEGMENT_ID: u64 = 4;

/// Encoding version of the body.
const VERSION: u64 = 1;

/// Most records held at once: every trusted identity removed in a generous number of closed rooms.
/// [`PendingLocks::insert`] holds no more; a removal past it is refused rather than half done.
const MAX_PENDING: usize = MAX_TRUSTED * 64;

/// `(room, member)` pairs: `member` was removed from the keyring while `room` was closed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PendingLocks {
    entries: BTreeSet<(Digest32, Digest32)>,
}

impl PendingLocks {
    /// Record that `member` was removed while `room` was closed. Whether it is recorded: a new
    /// entry past the bound is not.
    #[must_use]
    pub fn insert(&mut self, room: Digest32, member: Digest32) -> bool {
        if self.entries.len() >= MAX_PENDING && !self.entries.contains(&(room, member)) {
            return false;
        }
        self.entries.insert((room, member));
        true
    }

    /// The members removed while `room` was closed.
    #[must_use]
    pub fn for_room(&self, room: &Digest32) -> Vec<Digest32> {
        self.entries
            .iter()
            .filter(|(r, _)| r == room)
            .map(|(_, m)| *m)
            .collect()
    }

    /// `room` has acted on its records: forget them. Whether any were held.
    pub fn clear_room(&mut self, room: &Digest32) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(r, _)| r != room);
        self.entries.len() != before
    }

    /// `member` is trusted again: its removal no longer stands, in any room. Whether any were held.
    pub fn forget(&mut self, member: &Digest32) -> bool {
        let before = self.entries.len();
        self.entries.retain(|(_, m)| m != member);
        self.entries.len() != before
    }

    /// Canonical CBOR body: `[version, [[room, member], ..]]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2).uint(VERSION).array(self.entries.len());
        for (room, member) in &self.entries {
            e.array(2).bytes(room).bytes(member);
        }
        e.finish()
    }

    /// Parse a body.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let bad = |what| Error::MalformedAtRest(what);
        let mut d = Decoder::new(b);
        if d.array().map_err(|_| bad("pending locks"))? != 2 {
            return Err(bad("pending locks arity"));
        }
        if d.uint().map_err(|_| bad("pending locks version"))? != VERSION {
            return Err(bad("pending locks version"));
        }
        // Rows are read one at a time and nothing is sized from `n`; past the bound, rows are read
        // and not kept.
        let n = d.array().map_err(|_| bad("pending locks len"))?;
        let mut entries = BTreeSet::new();
        for _ in 0..n {
            if d.array().map_err(|_| bad("pending lock row"))? != 2 {
                return Err(bad("pending lock row arity"));
            }
            let room = Digest32::try_from(d.bytes().map_err(|_| bad("pending lock room"))?)
                .map_err(|_| bad("pending lock room length"))?;
            let member = Digest32::try_from(d.bytes().map_err(|_| bad("pending lock member"))?)
                .map_err(|_| bad("pending lock member length"))?;
            if entries.len() < MAX_PENDING {
                entries.insert((room, member));
            }
        }
        d.finish().map_err(|_| bad("pending locks trailing"))?;
        Ok(Self { entries })
    }

    /// Seal and write. Requires an unlocked identity.
    pub fn save(&self, store: &Store, signer: &dyn RootSigner) -> Result<()> {
        crate::node::at_rest::save_meta_blob(
            store,
            META_KEY,
            SEGMENT_ID,
            &pending_lock_sek(signer)?,
            &self.to_bytes(),
        )
    }

    /// Read and open, or an empty set if nothing was ever recorded. Requires an unlocked identity.
    pub fn load(store: &Store, signer: &dyn RootSigner) -> Result<Self> {
        match crate::node::at_rest::load_meta_blob(
            store,
            META_KEY,
            SEGMENT_ID,
            &pending_lock_sek(signer)?,
        )? {
            None => Ok(Self::default()),
            Some(plain) => Self::from_bytes(&plain),
        }
    }
}
