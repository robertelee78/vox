//! Where this node last reached each member — kept, so a node that restarts can find its
//! rooms again without an anchor.
//!
//! ## Why this exists
//!
//! A node learns where a member is from the rendezvous board, and the board lives in memory.
//! A member that restarted therefore came back knowing **no** member's address. Anchors are
//! redialled from configuration; members never were. In a room with no anchor the restarted
//! node stayed alone: its peers still held a connection to the process that had died, never
//! dialled again once it idled out, and nothing either side posted reached the other (found
//! by the R10 retention gate: `peers: []` on the restarted node, a post no member ever read).
//!
//! PRD-001 requires no anchor. Every peer-to-peer system that keeps working across restarts —
//! WireGuard's last endpoint, Tailscale's cached peer endpoints — does the same thing: it
//! remembers where each peer last answered. So this node keeps, for each member it has had a
//! **direct** connection with, the addresses it reached that member at, with when, and on
//! reopening a room dials them. If the restarted node kept its port, a member who remembered
//! it could reach it too; if it came back on a new one, it is the restarted node that dials,
//! and the member it reaches learns the new address from the connection.
//!
//! ## What is kept, and what is not
//!
//! Only the socket address of a direct connection, never a relay circuit's, which is an
//! artefact of this process and means nothing after it. At most [`MAX_ADDRS_PER_PEER`] per
//! member, most recent first, and at most [`MAX_PEERS`] members, oldest forgotten first, so a
//! blob can never grow without bound. It is who this node talks to and where, so it is sealed
//! under a key derived from this node's own identity (`vox/peer-book-sek/v1`), like the trust
//! keyring, and read only once the identity is unlocked.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::atrest::sek::{Sek, NONCE_LEN, SEK_LEN};
use crate::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32};
use crate::identity::composite::RootSigner;
use crate::nat::multiaddr::{EndpointList, Multiaddr};
use crate::node::store::Store;

/// HKDF label for the book's sealing key.
pub const PEER_BOOK_SEK_INFO: &[u8] = b"vox/peer-book-sek/v1";

/// Domain-separated context the identity factor is taken over.
pub const PEER_BOOK_CONTEXT_LABEL: &[u8] = b"vox/peer-book-context/v1";

/// The metadata key the sealed book is stored under.
pub const PEER_BOOK_META_KEY: &str = "peer-book";

/// Its segment id under [`SegmentKind::Trust`] — the keyring is 0; this is a different key and
/// a different id, so neither can be opened as the other.
const PEER_BOOK_SEGMENT_ID: u64 = 1;

/// Encoding version of the book body.
const PEER_BOOK_VERSION: u64 = 1;

/// Addresses kept per member.
pub const MAX_ADDRS_PER_PEER: usize = 4;

/// Members kept.
pub const MAX_PEERS: usize = 4096;

/// How stale a kept address's time may grow before a fresh sighting is worth a write. Seeing
/// the same address again is not news; persisting every connection would write the store on
/// every reconnect for nothing.
pub const REFRESH_SECS: u64 = 600;

fn peer_book_sek(signer: &dyn RootSigner) -> Result<Sek> {
    use crate::atrest::idfactor::{IdentityFactor, SignatureIdentityFactor};
    let context = sha256(PEER_BOOK_CONTEXT_LABEL);
    let factor = SignatureIdentityFactor::new(signer);
    let factor_id = factor.factor_id(&context)?;
    let hk = Hkdf::<Sha256>::new(None, factor_id.as_ref());
    let mut key = Zeroizing::new([0u8; SEK_LEN]);
    hk.expand(PEER_BOOK_SEK_INFO, key.as_mut())
        .map_err(|_| Error::AtRestUnlockFailed)?;
    Ok(Sek::from_bytes(key))
}

/// Where each member was last reached: `(address, last seen, unix seconds)`, most recent first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerBook {
    peers: BTreeMap<Digest32, Vec<(SocketAddr, u64)>>,
}

impl PeerBook {
    /// An empty book.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `peer` was reached directly at `addr` at `now`. Returns whether the book
    /// changed enough to be worth saving: a new address, or a known one last seen more than
    /// [`REFRESH_SECS`] ago.
    pub fn note(&mut self, peer: Digest32, addr: SocketAddr, now: u64) -> bool {
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_PEERS {
            // Forget whoever was seen longest ago.
            if let Some(oldest) = self
                .peers
                .iter()
                .min_by_key(|(_, a)| a.first().map_or(0, |(_, t)| *t))
                .map(|(p, _)| *p)
            {
                self.peers.remove(&oldest);
            }
        }
        let addrs = self.peers.entry(peer).or_default();
        let changed = match addrs.iter().position(|(a, _)| *a == addr) {
            Some(i) => {
                let (_, seen) = addrs.remove(i);
                now.saturating_sub(seen) >= REFRESH_SECS || i != 0
            }
            None => true,
        };
        addrs.insert(0, (addr, now));
        addrs.truncate(MAX_ADDRS_PER_PEER);
        changed
    }

    /// Where to dial `peer`, most recently seen first. Empty if it was never reached directly.
    #[must_use]
    pub fn endpoints(&self, peer: &Digest32) -> EndpointList {
        let addrs: Vec<Multiaddr> = self
            .peers
            .get(peer)
            .into_iter()
            .flatten()
            .map(|(a, _)| Multiaddr::from(*a))
            .collect();
        EndpointList::new(addrs).unwrap_or_default()
    }

    /// How many members the book knows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the book knows nobody.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Canonical CBOR body: `[version, [[peer, [[addr_text, seen], ..]], ..]]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2).uint(PEER_BOOK_VERSION).array(self.peers.len());
        for (peer, addrs) in &self.peers {
            e.array(2).bytes(peer).array(addrs.len());
            for (a, seen) in addrs {
                e.array(2).text(&a.to_string()).uint(*seen);
            }
        }
        e.finish()
    }

    /// Parse a book body. A malformed body is an error, never a partial book.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let bad = |what| Error::MalformedAtRest(what);
        let mut d = Decoder::new(b);
        if d.array().map_err(|_| bad("peer book"))? != 2
            || d.uint().map_err(|_| bad("peer book version"))? != PEER_BOOK_VERSION
        {
            return Err(bad("peer book version"));
        }
        let n = d.array().map_err(|_| bad("peer book len"))?;
        if n > MAX_PEERS {
            return Err(Error::SizeLimitExceeded("peer book"));
        }
        let mut peers = BTreeMap::new();
        for _ in 0..n {
            if d.array().map_err(|_| bad("peer book row"))? != 2 {
                return Err(bad("peer book row arity"));
            }
            let peer = Digest32::try_from(d.bytes().map_err(|_| bad("peer book id"))?)
                .map_err(|_| bad("peer book id length"))?;
            let m = d.array().map_err(|_| bad("peer book addrs"))?;
            if m > MAX_ADDRS_PER_PEER {
                return Err(Error::SizeLimitExceeded("peer book addresses"));
            }
            let mut addrs = Vec::with_capacity(m);
            for _ in 0..m {
                if d.array().map_err(|_| bad("peer book addr"))? != 2 {
                    return Err(bad("peer book addr arity"));
                }
                let addr: SocketAddr = d
                    .text()
                    .map_err(|_| bad("peer book addr text"))?
                    .parse()
                    .map_err(|_| bad("peer book addr parse"))?;
                let seen = d.uint().map_err(|_| bad("peer book seen"))?;
                addrs.push((addr, seen));
            }
            peers.insert(peer, addrs);
        }
        d.finish().map_err(|_| bad("peer book trailing"))?;
        Ok(Self { peers })
    }

    /// Seal and write the book. Requires an unlocked identity.
    pub fn save(&self, store: &Store, signer: &dyn RootSigner) -> Result<()> {
        let sek = peer_book_sek(signer)?;
        let sealed = seal_segment(
            &sek,
            SegmentKind::Trust,
            PEER_BOOK_SEGMENT_ID,
            &self.to_bytes(),
        )?;
        let mut blob = Vec::with_capacity(NONCE_LEN + sealed.ciphertext.len());
        blob.extend_from_slice(&sealed.nonce);
        blob.extend_from_slice(&sealed.ciphertext);
        store.put_meta(PEER_BOOK_META_KEY, &blob)
    }

    /// Read and open the book, or an empty one if this node has never reached anybody.
    /// Requires an unlocked identity.
    pub fn load(store: &Store, signer: &dyn RootSigner) -> Result<Self> {
        let Some(blob) = store.get_meta(PEER_BOOK_META_KEY)? else {
            return Ok(Self::new());
        };
        if blob.len() < NONCE_LEN {
            return Err(Error::MalformedAtRest("peer book blob too short"));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = <[u8; NONCE_LEN]>::try_from(nonce_bytes)
            .map_err(|_| Error::MalformedAtRest("peer book nonce"))?;
        let sealed = SealedSegment {
            nonce,
            ciphertext: ciphertext.to_vec(),
        };
        let sek = peer_book_sek(signer)?;
        let plain = open_segment(&sek, SegmentKind::Trust, PEER_BOOK_SEGMENT_ID, &sealed)?;
        Self::from_bytes(&plain)
    }
}
