//! **A Session is sealed to the members its node trusts with drive** (ADR-029 SC-2, SC-2a, SC-2b;
//! #543).
//!
//! Each node keeps, per room, a second sender-key chain beside its sender key: its **drive key**.
//! Every entry of every one of its Sessions in the room is sealed under it, and it is released only
//! to members whose keyring entry carries drive (ADR-028 K-14). One chain per (room, node), not one
//! per Session: drive is granted per keyring entry, so all of a node's Sessions have the same
//! readers, and a key per Session would only multiply the releases.
//!
//! It is the sender-key machinery (ADR-006) over its own namespace: the chain, its SKDMs and its
//! messages are bound to [`drive_channel`] rather than the room's id, so its AEAD data, its
//! cross-signature and its receiver slots can never be taken for the sender key's, nor the sender
//! key's for it. Its entries are ordinary content entries of the room's log (the skeleton is the
//! room's), so they sync, age and prune as messages do (SE-5).
//!
//! - **Release** (SC-2a): to each member admitted to the room whose keyring entry carries drive,
//!   from where it became owed the key, so it reads from then onward: a member that had drive when
//!   a generation was minted reads that generation whole, one that gained drive (or was admitted)
//!   later reads from that moment. Owed again at every new generation, retried on the tick. The
//!   cause of every release is that keyring entry (ADR-020 3.3).
//! - **Rotation** (SC-2b): when a member it was released to no longer has drive (downgraded to
//!   read, or untrusted), a new chain with fresh keys, released to the members that still have
//!   drive. The member keeps what it read and reads nothing sealed afterwards.
//! - **Receiving**: a drive key is taken only from a node this node trusts (V210-118), as the sender
//!   key is.
//!
//! The delivery ledger is local and sealed: the keyring is the authority on who may read, and the
//! ledger only says who has been given which generation.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::group::senderkey::ChainKey;
use crate::group::skdm::Skdm;
use crate::group::state::{ReceiverChain, SenderChain};
use crate::hash::Digest32;
use crate::identity::composite::RootSigner;

/// Domain of a room's drive namespace.
const DRIVE_DOMAIN: &[u8] = b"vox/session-key/v1";

/// Encoding version of the sealed drive state.
const DRIVE_VERSION: u64 = 2;

/// The most drive keys a room holds from other members, across generations.
pub const MAX_DRIVE_CHAINS: usize = 4096;

/// The id a room's drive keys are bound to in place of the room's own: `SHA-256(domain ‖ room)`.
#[must_use]
pub fn drive_channel(channel_id: &Digest32) -> Digest32 {
    crate::hash::sha256_concat(&[DRIVE_DOMAIN, channel_id])
}

/// One Session entry this node opened, or wrote (ADR-029 SC-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    /// The entry's ADR-008 hash.
    pub entry_hash: Digest32,
    /// The node whose session it is: the entry's author.
    pub author: Digest32,
    /// The author's recorded send time, milliseconds since the Unix epoch.
    pub created_millis: u64,
    /// The harness's session id.
    pub session_id: String,
    /// The activity item, as the harness's format has it.
    pub body: String,
}

/// A room's drive key material: this node's own chain, the drive keys other members released to
/// it, and to whom this node has released which generation.
#[derive(Default)]
pub struct DriveState {
    /// This node's drive chain here; none until its first Session entry in the room.
    pub(crate) chain: Option<SenderChain>,
    /// The live generation's iteration-0 key, from which each release is made at its mark.
    origin: Option<ChainKey>,
    /// Member → `(generation, iteration)` from which it is owed this node's drive key: where the
    /// live generation stood when it became owed it.
    marks: BTreeMap<Digest32, (u64, u64)>,
    /// Drive keys released to this node, by `(author, generation)`.
    pub(crate) receivers: BTreeMap<(Digest32, u64), ReceiverChain>,
    /// Member → the generation of this node's drive key last released to it.
    pub(crate) delivered: BTreeMap<Digest32, u64>,
    /// The Session entries opened or written here, in the order they were.
    pub(crate) sessions: Vec<SessionRow>,
    /// Entries opened in a render pass, placed once its batch has committed.
    pub(crate) pending: Vec<(SessionRow, u64)>,
}

impl DriveState {
    /// Make `chain` this node's live drive generation, marking every member of `holders` owed it
    /// from its first entry.
    pub fn begin(&mut self, chain: SenderChain, holders: impl IntoIterator<Item = Digest32>) {
        let (_, origin) = chain.current_position();
        let live = chain.chain_id();
        self.marks = holders.into_iter().map(|m| (m, (live, 0))).collect();
        self.origin = Some(origin);
        self.chain = Some(chain);
    }

    /// The members owed this node's live drive key: each of `members` (the room's, this node
    /// excepted) that `drive` names and that has not been released the live generation. A member
    /// owed it for the first time is marked owed from the chain's position now.
    pub fn take_owed(
        &mut self,
        members: &BTreeSet<Digest32>,
        drive: &BTreeSet<Digest32>,
    ) -> Vec<Digest32> {
        let Some(chain) = &self.chain else {
            return Vec::new();
        };
        let (live, now) = (chain.chain_id(), chain.next_iteration());
        let owed: Vec<Digest32> = members
            .iter()
            .filter(|m| drive.contains(*m))
            .filter(|m| self.delivered.get(*m) != Some(&live))
            .copied()
            .collect();
        for m in &owed {
            let mark = self.marks.entry(*m).or_insert((live, now));
            if mark.0 != live {
                *mark = (live, now);
            }
        }
        owed
    }

    /// The SKDM releasing the live drive key to `member` from its mark, and the generation it
    /// releases.
    pub fn release_for(&self, signer: &dyn RootSigner, member: &Digest32) -> Result<(Skdm, u64)> {
        let (Some(chain), Some(origin)) = (&self.chain, &self.origin) else {
            return Err(Error::Profile("this node has no drive key in the room"));
        };
        let live = chain.chain_id();
        let from = match self.marks.get(member) {
            Some((g, i)) if *g == live => *i,
            _ => chain.next_iteration(),
        };
        let mut key = origin.clone();
        for _ in 0..from {
            key = key.advance()?;
        }
        Ok((chain.skdm_for(signer, from, key)?, live))
    }

    /// Record that `member` holds generation `generation`.
    pub fn note_delivered(&mut self, member: Digest32, generation: u64) {
        self.delivered.insert(member, generation);
    }

    /// Forget `members` as holders of this node's drive key: they lost drive, and the key that
    /// replaces it is not theirs (SC-2b).
    pub fn forget(&mut self, members: &[Digest32]) {
        for m in members {
            self.delivered.remove(m);
            self.marks.remove(m);
        }
    }

    /// The members released this node's drive key that `drive` no longer names: each one is why
    /// the key must change (SC-2b).
    #[must_use]
    pub fn lost(&self, drive: &BTreeSet<Digest32>) -> Vec<Digest32> {
        self.delivered
            .keys()
            .filter(|m| !drive.contains(*m))
            .copied()
            .collect()
    }

    /// Whether this node holds any drive key of `author`'s.
    #[must_use]
    pub fn holds_from(&self, author: &Digest32) -> bool {
        self.receivers.keys().any(|(a, _)| a == author)
    }

    /// The sealed state: `[version, chain state or empty, origin key or empty, [receiver state,
    /// …], [[member, generation], …], [[member, generation, iteration], …]]`. Secret-bearing, so
    /// the buffer zeroizes on drop.
    #[must_use]
    pub fn to_state(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::for_secrets();
        e.array(6).uint(DRIVE_VERSION);
        match &self.chain {
            Some(c) => e.bytes(&c.to_state()),
            None => e.bytes(&[]),
        };
        match &self.origin {
            Some(o) => e.bytes(o.bytes()),
            None => e.bytes(&[]),
        };
        e.array(self.receivers.len());
        for r in self.receivers.values() {
            e.bytes(&r.to_state());
        }
        e.array(self.delivered.len());
        for (m, g) in &self.delivered {
            e.array(2).bytes(m).uint(*g);
        }
        e.array(self.marks.len());
        for (m, (g, i)) in &self.marks {
            e.array(3).bytes(m).uint(*g).uint(*i);
        }
        Zeroizing::new(e.finish())
    }

    /// Strict decode of [`Self::to_state`]. The Session rows come from the plaintext cache.
    pub fn from_state(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 6 || d.uint()? != DRIVE_VERSION {
            return Err(Error::MalformedAtRest("drive state version"));
        }
        let chain = match d.bytes()? {
            [] => None,
            state => Some(SenderChain::from_state(state)?),
        };
        let origin = match d.bytes()? {
            [] => None,
            key => Some(ChainKey::from_bytes(
                key.try_into()
                    .map_err(|_| Error::MalformedAtRest("drive origin key"))?,
            )),
        };
        let n = d.array()?;
        if n > MAX_DRIVE_CHAINS {
            return Err(Error::SizeLimitExceeded("room drive keys"));
        }
        let mut receivers = BTreeMap::new();
        for _ in 0..n {
            let r = ReceiverChain::from_state(d.bytes()?)?;
            receivers.insert((r.author_id(), r.chain_id()), r);
        }
        let n = d.array()?;
        let mut delivered = BTreeMap::new();
        for _ in 0..n {
            if d.array()? != 2 {
                return Err(Error::MalformedAtRest("drive ledger row"));
            }
            let m: Digest32 = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("drive ledger member"))?;
            delivered.insert(m, d.uint()?);
        }
        let n = d.array()?;
        let mut marks = BTreeMap::new();
        for _ in 0..n {
            if d.array()? != 3 {
                return Err(Error::MalformedAtRest("drive mark row"));
            }
            let m: Digest32 = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("drive mark member"))?;
            marks.insert(m, (d.uint()?, d.uint()?));
        }
        d.finish()?;
        Ok(Self {
            chain,
            origin,
            marks,
            receivers,
            delivered,
            sessions: Vec::new(),
            pending: Vec::new(),
        })
    }
}
