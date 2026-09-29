//! An author's **checkpoint** on its own feed (ADR-023 decision 3, tag `0x0015`,
//! domain `vox/checkpoint/v1`).
//!
//! A room that keeps messages for a while still keeps every signed skeleton forever, and the
//! composite signature is 3,373 of the roughly 3.7 KB each one costs. A checkpoint lets that
//! go. It is the payload of an ordinary log entry in its author's own feed, so the entry's
//! composite signature covers it, and it names one position of that same feed:
//! `(seq, entry_hash)`, below which the author's skeletons are past the room's retention.
//!
//! A node holding it may drop the signatures of that author's entries at or below `seq`
//! whose bodies it has already pruned. They stay authentic through the hash chain: the signed
//! checkpoint names `entry_hash` at `seq`, and every entry below it is named by its
//! successor's `prev_hash`. And an entry arriving for a position at or below it that the node
//! does not already hold is refused as pre-checkpoint, never raised as a fork: it could never
//! be shown (its body is expired), and a fork proof below the line would need the very
//! signature the checkpoint lets nodes drop.
//!
//! **Why the author posts it, for its own feed only.** The checkpoint must be believed by
//! every node without further evidence, and the only party whose signature already vouches
//! for a feed is its author: the checkpoint's position is on the author's own hash chain, so
//! it adds no trust that the feed's signatures did not already carry. A checkpoint by anyone
//! else about someone else's feed would let one member make every node forget another's
//! signatures — the evidence that member would need to prove a fork. The cost is that an
//! author who never comes back never checkpoints, and its old skeletons keep their signatures;
//! that is the conservative failure.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::wire::{frame, parse_frame, StructTag};

/// A checkpoint's claim: the author's entry at `seq` has hash `entry_hash`, and everything at
/// or below it is past retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// The position in the author's own feed.
    pub seq: u64,
    /// The hash of the author's entry at `seq`.
    pub entry_hash: Digest32,
}

impl Checkpoint {
    /// The framed payload: `tag(0x0015) ‖ version ‖ [seq, entry_hash]`.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2).uint(self.seq).bytes(&self.entry_hash);
        frame(StructTag::Checkpoint, &e.finish())
    }

    /// Parse a payload as a checkpoint: `Ok(None)` when it is some other kind of payload,
    /// an error when it claims to be a checkpoint and is malformed.
    pub fn from_payload(payload: &[u8]) -> Result<Option<Self>> {
        let Ok(parsed) = parse_frame(payload) else {
            return Ok(None);
        };
        if parsed.tag != StructTag::Checkpoint {
            return Ok(None);
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 2 {
            return Err(Error::MalformedBundle("checkpoint arity"));
        }
        let seq = d.uint()?;
        let entry_hash: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("checkpoint entry hash"))?;
        d.finish()?;
        if seq == 0 {
            return Err(Error::MalformedBundle("checkpoint at seq 0"));
        }
        Ok(Some(Self { seq, entry_hash }))
    }
}
