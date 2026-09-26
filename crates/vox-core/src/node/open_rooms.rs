//! **The rooms a node reopens by itself** (#208, V210-35).
//!
//! A room is sealed at rest under its SEK, and the SEK is wrapped under the room's passphrase
//! *and* this identity (ADR-010). Opening a room therefore needed its passphrase, which a
//! `vox daemon` never has: it unlocks with the identity passphrase alone. A daemon that restarted
//! came back holding none of its rooms, and every `vox room` verb answered "not open on this
//! node" until somebody opened each one in the interactive `vox tui`. An agent machine running
//! only a daemon lost every room at every reboot.
//!
//! The decider's rule: **a daemon reopens every room that was open** when it unlocks. So each
//! open room's SEK is also kept here, with its passphrase (an open room retains that to answer
//! joins, ADR-005, and a reopened room that could not would admit nobody), sealed under a key
//! derived from this identity alone.
//!
//! **Which identity secret, and why not the one the trust keyring uses.** The keyring
//! ([`crate::node::trust`]) is sealed under HKDF of the identity's deterministic **Ed25519**
//! signature. That is classical: ADR-010 says so, and rests a room's post-quantum strength at rest
//! on the Argon2id room-passphrase factor instead. A set sealed that way would take the room
//! passphrase out and leave only Ed25519 — and the Ed25519 key follows from the *public* key for a
//! quantum adversary, so every remembered room would open from the disk with **no passphrase at
//! all**. So this set is sealed under HKDF of the identity's `self_seed`: 32 random bytes that
//! exist only inside the identity vault, which is sealed under Argon2id of the identity passphrase
//! at the at-rest floor (≥256 MiB, ≥3 passes). The set is therefore exactly as hard to open as the
//! identity vault itself, classically and post-quantum — the bar the decider set. A room enters the set when it is
//! created, joined or opened, and leaves it only when it is **closed on purpose**: a process
//! that stops without closing (a restart, a crash, a reboot) reopens what it held.
//!
//! What this changes, stated plainly: with this set, **the identity passphrase alone opens the
//! rooms in it**. The room passphrase still guards joining, and it still guards any room that was
//! closed on purpose, but a stolen disk plus the identity passphrase now yields the open rooms
//! too. That is the cost of a service that comes back as it was, and the decider chose it.
//!
//! The sealed blob sits in the store's public metadata table, like the keyring's: ciphertext is a
//! public fact.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::atrest::sek::{Sek, NONCE_LEN, SEK_LEN};
use crate::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use crate::atrest::vault::VaultRootSigner;
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::store::Store;

/// The metadata key the sealed set is stored under.
pub const OPEN_ROOMS_META_KEY: &str = "open-rooms";

/// HKDF info for the set's sealing key, over `self_seed`. Distinct from every other label taken
/// over `self_seed` (the self-channel's), so no other key derived from it opens this blob.
pub const OPEN_ROOMS_SEK_INFO: &[u8] = b"vox/open-rooms-sek/v1";

/// Only slot; the set is a single blob.
const OPEN_ROOMS_SEGMENT_ID: u64 = 0;

/// Encoding version of the set's body.
const OPEN_ROOMS_VERSION: u64 = 1;

/// Longest room passphrase the set will hold. A bound on what a corrupt blob can make it
/// allocate, far above any passphrase a person types.
pub const MAX_ROOM_PASSPHRASE: usize = 4096;

/// Most rooms one node will reopen. A bound, not a target: a corrupt or hostile blob cannot force
/// an unbounded allocation on load.
pub const MAX_OPEN_ROOMS: usize = 4096;

/// The sealing key for this identity's set of open rooms.
fn open_rooms_sek(signer: &VaultRootSigner) -> Result<Sek> {
    let hk = Hkdf::<Sha256>::new(None, signer.self_seed());
    let mut key = Zeroizing::new([0u8; SEK_LEN]);
    hk.expand(OPEN_ROOMS_SEK_INFO, key.as_mut())
        .map_err(|_| Error::AtRestUnlockFailed)?;
    Ok(Sek::from_bytes(key))
}

/// What reopens one room: its SEK, and the passphrase it answers joins with.
pub struct RoomKeys {
    /// The room's at-rest key.
    pub sek: Zeroizing<[u8; SEK_LEN]>,
    /// The room passphrase, retained so the reopened room can answer joins.
    pub passphrase: Zeroizing<Vec<u8>>,
}

/// The rooms this node reopens by itself.
#[derive(Default)]
pub struct OpenRooms {
    rooms: BTreeMap<Digest32, RoomKeys>,
}

impl OpenRooms {
    /// The rooms in the set, in channelID order.
    pub fn rooms(&self) -> impl Iterator<Item = (&Digest32, &RoomKeys)> {
        self.rooms.iter()
    }

    /// Remember `channel_id` as open, with the keys that reopen it. Returns whether the set
    /// changed.
    pub fn remember(
        &mut self,
        channel_id: Digest32,
        sek: &[u8],
        passphrase: &[u8],
    ) -> Result<bool> {
        let key = <[u8; SEK_LEN]>::try_from(sek)
            .map_err(|_| Error::MalformedAtRest("open room SEK length"))?;
        if passphrase.is_empty() || passphrase.len() > MAX_ROOM_PASSPHRASE {
            return Err(Error::SizeLimitExceeded("open room passphrase"));
        }
        if self
            .rooms
            .get(&channel_id)
            .is_some_and(|k| *k.sek == key && k.passphrase.as_slice() == passphrase)
        {
            return Ok(false);
        }
        if !self.rooms.contains_key(&channel_id) && self.rooms.len() >= MAX_OPEN_ROOMS {
            return Err(Error::SizeLimitExceeded("open rooms"));
        }
        self.rooms.insert(
            channel_id,
            RoomKeys {
                sek: Zeroizing::new(key),
                passphrase: Zeroizing::new(passphrase.to_vec()),
            },
        );
        Ok(true)
    }

    /// Forget `channel_id`: a room closed on purpose is not reopened. Returns whether it was there.
    pub fn forget(&mut self, channel_id: &Digest32) -> bool {
        self.rooms.remove(channel_id).is_some()
    }

    fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(2).uint(OPEN_ROOMS_VERSION).array(self.rooms.len());
        for (id, keys) in &self.rooms {
            e.array(3)
                .bytes(id)
                .bytes(keys.sek.as_ref())
                .bytes(&keys.passphrase);
        }
        Zeroizing::new(e.finish())
    }

    fn from_bytes(b: &[u8]) -> Result<Self> {
        let bad = |why: &'static str| Error::MalformedAtRest(why);
        let mut d = Decoder::new(b);
        if d.array().map_err(|_| bad("open rooms"))? != 2 {
            return Err(bad("open rooms arity"));
        }
        if d.uint().map_err(|_| bad("open rooms version"))? != OPEN_ROOMS_VERSION {
            return Err(bad("open rooms version"));
        }
        let n = d.array().map_err(|_| bad("open rooms list"))?;
        if n > MAX_OPEN_ROOMS {
            return Err(bad("open rooms count"));
        }
        let mut rooms = BTreeMap::new();
        for _ in 0..n {
            if d.array().map_err(|_| bad("open room"))? != 3 {
                return Err(bad("open room arity"));
            }
            let id = Digest32::try_from(d.bytes().map_err(|_| bad("open room id"))?)
                .map_err(|_| bad("open room id length"))?;
            let key = <[u8; SEK_LEN]>::try_from(d.bytes().map_err(|_| bad("open room SEK"))?)
                .map_err(|_| bad("open room SEK length"))?;
            let passphrase = d.bytes().map_err(|_| bad("open room passphrase"))?;
            if passphrase.is_empty() || passphrase.len() > MAX_ROOM_PASSPHRASE {
                return Err(bad("open room passphrase length"));
            }
            rooms.insert(
                id,
                RoomKeys {
                    sek: Zeroizing::new(key),
                    passphrase: Zeroizing::new(passphrase.to_vec()),
                },
            );
        }
        d.finish().map_err(|_| bad("open rooms trailing"))?;
        Ok(Self { rooms })
    }

    /// Seal and write the set. Requires an unlocked identity.
    pub fn save(&self, store: &Store, signer: &VaultRootSigner) -> Result<()> {
        let sek = open_rooms_sek(signer)?;
        let sealed = seal_segment(
            &sek,
            SegmentKind::Trust,
            OPEN_ROOMS_SEGMENT_ID,
            &self.to_bytes(),
        )?;
        let mut blob = Vec::with_capacity(NONCE_LEN + sealed.ciphertext.len());
        blob.extend_from_slice(&sealed.nonce);
        blob.extend_from_slice(&sealed.ciphertext);
        store.put_meta(OPEN_ROOMS_META_KEY, &blob)
    }

    /// Read and open the set, or an empty one if this node has never held a room open. Requires an
    /// unlocked identity.
    pub fn load(store: &Store, signer: &VaultRootSigner) -> Result<Self> {
        let Some(blob) = store.get_meta(OPEN_ROOMS_META_KEY)? else {
            return Ok(Self::default());
        };
        if blob.len() < NONCE_LEN {
            return Err(Error::MalformedAtRest("open rooms blob too short"));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = <[u8; NONCE_LEN]>::try_from(nonce_bytes)
            .map_err(|_| Error::MalformedAtRest("open rooms nonce"))?;
        let sealed = SealedSegment {
            nonce,
            ciphertext: ciphertext.to_vec(),
        };
        let sek = open_rooms_sek(signer)?;
        let plain = Zeroizing::new(open_segment(
            &sek,
            SegmentKind::Trust,
            OPEN_ROOMS_SEGMENT_ID,
            &sealed,
        )?);
        Self::from_bytes(&plain)
    }
}
