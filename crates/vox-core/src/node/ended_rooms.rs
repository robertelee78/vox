//! **The rooms this node deleted because they ended for everyone** (V030-08, #1206).
//!
//! An ended room is passed on and deleted, name and all, so a member who then named it was told
//! `nothing here matches "<room>"`: the same words as a typo. The decider wants the reason. So a
//! node keeps a short record of the rooms it deleted for having ended — the room, its name, who
//! ended it and when — and `vox room` verbs say "room <name> was ended for everyone by <who> at
//! <time>" for as long as the record holds it.
//!
//! The record is bounded ([`KEPT`] rooms, [`KEPT_MS`] old): it exists to explain a recent
//! absence, not to remember every room ever. It is sealed under this identity like the keyring
//! and the dismissed offers ([`crate::node::offers`]): a room's name is sealed in its manifest,
//! and does not become a public fact by the room ending.

use crate::atrest::sek::{Sek, NONCE_LEN};
use crate::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::RootSigner;
use crate::node::store::{Batch, Store};

/// HKDF label for the record's sealing key, taken over `self_seed` ([`crate::atrest::seal`]).
pub const ENDED_ROOMS_SEK_INFO: &[u8] = b"vox/ended-rooms-sek/v1";

/// The metadata key the sealed record is stored under.
pub const META_KEY: &str = "ended-rooms";

/// Its slot within [`SegmentKind::Trust`].
const SEGMENT_ID: u64 = 6;

/// Encoding version of the body.
const VERSION: u64 = 1;

/// Most ended rooms remembered; the oldest noted goes first past it.
pub const KEPT: usize = 64;

/// How long an ended room is remembered after this node noted its end: 30 days.
pub const KEPT_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

/// Longest room name kept, in bytes: a room name is one DNS label (ADR-028 R-1).
const MAX_NAME: usize = 63;

/// One room this node deleted because it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndedRoom {
    /// The room.
    pub channel_id: Digest32,
    /// Its local name when it ended, if it had one.
    pub name: Option<String>,
    /// Who ended it: the creator or admin whose entry ended it, or `None` for the idle end its
    /// creator chose.
    pub by: Option<Digest32>,
    /// When it ended, unix milliseconds, by the room's own clock.
    pub ended_ms: u64,
    /// When this node noted the end (and deleted the room), unix milliseconds.
    pub noted_ms: u64,
}

/// The record, newest noted last.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EndedRooms {
    rooms: Vec<EndedRoom>,
}

impl EndedRooms {
    /// The rooms still within [`KEPT_MS`] at `now_ms`, oldest noted first: what is published
    /// and served, so a note is not shown past its bound only because nothing ended since.
    #[must_use]
    pub fn current(&self, now_ms: u64) -> Vec<EndedRoom> {
        self.rooms
            .iter()
            .filter(|room| now_ms.saturating_sub(room.noted_ms) <= KEPT_MS)
            .cloned()
            .collect()
    }

    /// Note `room`'s end at `now_ms`, forgetting an earlier note of the same room and whatever
    /// the bounds no longer keep.
    pub fn note(&mut self, mut room: EndedRoom, now_ms: u64) {
        room.noted_ms = now_ms;
        self.rooms.retain(|kept| kept.channel_id != room.channel_id);
        self.rooms.push(room);
        self.prune(now_ms);
    }

    /// Drop what the bounds no longer keep.
    pub fn prune(&mut self, now_ms: u64) {
        self.rooms
            .retain(|room| now_ms.saturating_sub(room.noted_ms) <= KEPT_MS);
        if self.rooms.len() > KEPT {
            let excess = self.rooms.len() - KEPT;
            self.rooms.drain(..excess);
        }
    }

    /// Canonical CBOR body: `[version, [[room, name, by, ended_ms, noted_ms], ..]]`; an absent
    /// name or ender is empty bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2).uint(VERSION).array(self.rooms.len());
        for room in &self.rooms {
            e.array(5)
                .bytes(&room.channel_id)
                .text(room.name.as_deref().unwrap_or_default())
                .bytes(room.by.as_ref().map_or(&[][..], |by| &by[..]))
                .uint(room.ended_ms)
                .uint(room.noted_ms);
        }
        e.finish()
    }

    /// Parse a body.
    ///
    /// # Errors
    /// A body that is not one [`Self::to_bytes`] writes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let bad = Error::MalformedAtRest;
        let mut d = Decoder::new(b);
        if d.array().map_err(|_| bad("ended rooms"))? != 2 {
            return Err(bad("ended rooms arity"));
        }
        if d.uint().map_err(|_| bad("ended rooms version"))? != VERSION {
            return Err(bad("ended rooms version"));
        }
        let n = d.array().map_err(|_| bad("ended rooms len"))?;
        if n > KEPT {
            return Err(Error::SizeLimitExceeded("ended rooms"));
        }
        let mut rooms = Vec::with_capacity(n);
        for _ in 0..n {
            if d.array().map_err(|_| bad("ended room"))? != 5 {
                return Err(bad("ended room arity"));
            }
            let channel_id = Digest32::try_from(d.bytes().map_err(|_| bad("ended room id"))?)
                .map_err(|_| bad("ended room id length"))?;
            let name = d.text().map_err(|_| bad("ended room name"))?;
            if name.len() > MAX_NAME {
                return Err(bad("ended room name length"));
            }
            let name = (!name.is_empty()).then(|| name.to_owned());
            let by = d.bytes().map_err(|_| bad("ended room by"))?;
            let by = if by.is_empty() {
                None
            } else {
                Some(Digest32::try_from(by).map_err(|_| bad("ended room by length"))?)
            };
            let ended_ms = d.uint().map_err(|_| bad("ended room ended"))?;
            let noted_ms = d.uint().map_err(|_| bad("ended room noted"))?;
            rooms.push(EndedRoom {
                channel_id,
                name,
                by,
                ended_ms,
                noted_ms,
            });
        }
        d.finish().map_err(|_| bad("ended rooms trailing"))?;
        Ok(Self { rooms })
    }

    /// Queue the sealed record into `batch`. Requires an unlocked identity.
    ///
    /// # Errors
    /// The identity is locked, or the store cannot be written.
    pub fn queue_save(&self, batch: &mut Batch<'_>, signer: &dyn RootSigner) -> Result<()> {
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

    /// Read and open, or an empty record if no room ended here yet. Requires an unlocked
    /// identity.
    ///
    /// # Errors
    /// The identity is locked, or what is stored does not open.
    pub fn load(store: &Store, signer: &dyn RootSigner) -> Result<Self> {
        let Some(blob) = store.get_meta(META_KEY)? else {
            return Ok(Self::default());
        };
        if blob.len() < NONCE_LEN {
            return Err(Error::MalformedAtRest("ended rooms blob too short"));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = <[u8; NONCE_LEN]>::try_from(nonce_bytes)
            .map_err(|_| Error::MalformedAtRest("ended rooms nonce"))?;
        let sealed = SealedSegment {
            nonce,
            ciphertext: ciphertext.to_vec(),
        };
        let plain = open_segment(&sek(signer)?, SegmentKind::Trust, SEGMENT_ID, &sealed)?;
        Self::from_bytes(&plain)
    }
}

fn sek(signer: &dyn RootSigner) -> Result<Sek> {
    crate::atrest::seal::sek(signer, ENDED_ROOMS_SEK_INFO)
}

/// Note `room`'s end in the store's record, in `batch`: read after writer admission, so a note
/// never replaces a newer record with an older snapshot. A record that does not open is a
/// courtesy lost, not a reason to keep an ended room: it is replaced. Returns the record as
/// written.
///
/// # Errors
/// The identity is locked, or the record cannot be written.
pub fn note(
    store: &Store,
    batch: &mut Batch<'_>,
    signer: &dyn RootSigner,
    room: EndedRoom,
    now_ms: u64,
) -> Result<EndedRooms> {
    let mut next = EndedRooms::load(store, signer).unwrap_or_default();
    next.note(room, now_ms);
    next.queue_save(batch, signer)?;
    Ok(next)
}
