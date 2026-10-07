//! Trust offers (ADR-028 K-15 – K-18): which members a node is offered to put in its keyring, and
//! which offers it has dismissed.
//!
//! An offer is derived, never written to a room: a member of a room this node shares, not in its
//! keyring, that joined after this node did (K-15) or that grants this node consent (K-17,
//! [`crate::node::channel::ChannelState::offer_bases`]). It waits until it is accepted (the member
//! is then in the keyring), dismissed, or the member leaves (K-18). A dismissal is this node's
//! alone and silent: it is kept, sealed, against the entries the offer rests on, so the member
//! leaving and joining again, or granting consent again, offers it afresh.

use std::collections::{BTreeMap, BTreeSet};

use crate::atrest::sek::{Sek, NONCE_LEN};
use crate::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::RootSigner;
use crate::node::api::{ChannelDetail, Offer, OfferBasis, OfferRoom, OfferWhy};
use crate::node::store::Store;

/// HKDF label for the dismissals' sealing key, taken over `self_seed` ([`crate::atrest::seal`]).
pub const DISMISSED_OFFERS_SEK_INFO: &[u8] = b"vox/dismissed-offers-sek/v1";

/// The metadata key the sealed set is stored under.
pub const META_KEY: &str = "dismissed-offers";

/// Its slot within [`SegmentKind::Trust`].
const SEGMENT_ID: u64 = 5;

/// Encoding version of the body.
const VERSION: u64 = 1;

/// Most dismissals kept. The oldest go first past it: a dismissal past the bound only means an
/// offer that was dismissed long ago may be shown again.
const MAX_DISMISSED: usize = 4096;

/// The offers this node dismissed: `(room, the entry the offer rested on)`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DismissedOffers {
    entries: BTreeSet<(Digest32, OfferBasis)>,
}

impl DismissedOffers {
    /// Whether the offer resting on `basis` in `room` was dismissed.
    #[must_use]
    pub fn contains(&self, room: &Digest32, basis: &OfferBasis) -> bool {
        self.entries.contains(&(*room, *basis))
    }

    /// Dismiss what `member` is offered on now, in every room of `rooms`. Returns whether anything
    /// was added.
    pub fn dismiss(&mut self, member: &Digest32, rooms: &[ChannelDetail]) -> bool {
        let before = self.entries.len();
        for room in rooms {
            for b in room.offer_bases.iter().filter(|b| b.member == *member) {
                self.entries.insert((room.channel_id, *b));
            }
        }
        while self.entries.len() > MAX_DISMISSED {
            let first = self.entries.iter().next().copied();
            if let Some(first) = first {
                self.entries.remove(&first);
            }
        }
        self.entries.len() != before
    }

    /// Canonical CBOR body: `[version, [[room, member, why, seq], ..]]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2).uint(VERSION).array(self.entries.len());
        for (room, b) in &self.entries {
            e.array(4)
                .bytes(room)
                .bytes(&b.member)
                .uint(match b.why {
                    OfferWhy::Joined => 0,
                    OfferWhy::TrustsYou => 1,
                })
                .uint(b.seq);
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
        if d.array().map_err(|_| bad("dismissed offers"))? != 2 {
            return Err(bad("dismissed offers arity"));
        }
        if d.uint().map_err(|_| bad("dismissed offers version"))? != VERSION {
            return Err(bad("dismissed offers version"));
        }
        let n = d.array().map_err(|_| bad("dismissed offers len"))?;
        if n > MAX_DISMISSED {
            return Err(Error::SizeLimitExceeded("dismissed offers"));
        }
        let mut entries = BTreeSet::new();
        let digest = |d: &mut Decoder, what| {
            Digest32::try_from(d.bytes().map_err(|_| bad(what))?).map_err(|_| bad(what))
        };
        for _ in 0..n {
            if d.array().map_err(|_| bad("dismissed offer"))? != 4 {
                return Err(bad("dismissed offer arity"));
            }
            let room = digest(&mut d, "dismissed offer room")?;
            let member = digest(&mut d, "dismissed offer member")?;
            let why = match d.uint().map_err(|_| bad("dismissed offer why"))? {
                0 => OfferWhy::Joined,
                1 => OfferWhy::TrustsYou,
                _ => return Err(bad("dismissed offer why")),
            };
            let seq = d.uint().map_err(|_| bad("dismissed offer seq"))?;
            entries.insert((room, OfferBasis { member, why, seq }));
        }
        d.finish().map_err(|_| bad("dismissed offers trailing"))?;
        Ok(Self { entries })
    }

    /// Seal and write. Requires an unlocked identity.
    ///
    /// # Errors
    /// The identity is locked, or the store cannot be written.
    pub fn save(&self, store: &Store, signer: &dyn RootSigner) -> Result<()> {
        let sek = sek(signer)?;
        let sealed = seal_segment(&sek, SegmentKind::Trust, SEGMENT_ID, &self.to_bytes())?;
        let mut blob = Vec::with_capacity(NONCE_LEN + sealed.ciphertext.len());
        blob.extend_from_slice(&sealed.nonce);
        blob.extend_from_slice(&sealed.ciphertext);
        store.put_meta(META_KEY, &blob)
    }

    /// Read and open, or an empty set if nothing was ever dismissed. Requires an unlocked identity.
    ///
    /// # Errors
    /// The identity is locked, or what is stored does not open.
    pub fn load(store: &Store, signer: &dyn RootSigner) -> Result<Self> {
        let Some(blob) = store.get_meta(META_KEY)? else {
            return Ok(Self::default());
        };
        if blob.len() < NONCE_LEN {
            return Err(Error::MalformedAtRest("dismissed offers blob too short"));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = <[u8; NONCE_LEN]>::try_from(nonce_bytes)
            .map_err(|_| Error::MalformedAtRest("dismissed offers nonce"))?;
        let sealed = SealedSegment {
            nonce,
            ciphertext: ciphertext.to_vec(),
        };
        let plain = open_segment(&sek(signer)?, SegmentKind::Trust, SEGMENT_ID, &sealed)?;
        Self::from_bytes(&plain)
    }
}

fn sek(signer: &dyn RootSigner) -> Result<Sek> {
    crate::atrest::seal::sek(signer, DISMISSED_OFFERS_SEK_INFO)
}

/// What is gathered of one member over the rooms: its rooms, its reasons, and who of the keyring
/// trusts it.
type Gathered = (Vec<OfferRoom>, Vec<OfferWhy>, BTreeSet<Digest32>);

/// The members offered to this node's keyring over its open `rooms` (ADR-028 K-15 – K-18): each
/// member with an offer basis in some room that is not dismissed, and not in `keyring`
/// (`(fingerprint, alias)`), in fingerprint order. `names_here` is every room's name on this node,
/// so a room is named as the node shows it.
#[must_use]
pub fn offers(
    rooms: &[ChannelDetail],
    names_here: &[Option<String>],
    keyring: &[(Digest32, String)],
    dismissed: &DismissedOffers,
) -> Vec<Offer> {
    let in_keyring = |fp: &Digest32| keyring.iter().any(|(k, _)| k == fp);
    // Per member: its rooms, its reasons, and who of the keyring trusts it.
    let mut by: BTreeMap<Digest32, Gathered> = BTreeMap::new();
    for room in rooms {
        for b in &room.offer_bases {
            if in_keyring(&b.member) || dismissed.contains(&room.channel_id, b) {
                continue;
            }
            let (in_rooms, why, trusters) = by.entry(b.member).or_default();
            if !in_rooms.iter().any(|r| r.id == room.channel_id) {
                in_rooms.push(OfferRoom {
                    id: room.channel_id,
                    name: crate::node::resolver::room_shown_here(
                        room.name.as_deref(),
                        &room.channel_id,
                        names_here.iter().map(Option::as_deref),
                    ),
                });
            }
            if !why.contains(&b.why) {
                why.push(b.why);
            }
            if let Some((_, t)) = room.trusted_by.iter().find(|(m, _)| *m == b.member) {
                trusters.extend(t.iter().filter(|t| in_keyring(t)));
            }
        }
    }
    by.into_iter()
        .map(|(member, (mut in_rooms, mut why, trusters))| {
            in_rooms.sort_by(|a, b| a.id.cmp(&b.id));
            why.sort_unstable();
            let trusted_by: Vec<Digest32> = trusters.into_iter().collect();
            let names: Vec<String> = trusted_by
                .iter()
                .map(|t| {
                    let alias = keyring
                        .iter()
                        .find(|(k, _)| k == t)
                        .map(|(_, a)| a.as_str());
                    vox_text::offer::name(alias, &crate::node::link::b32_encode(t))
                })
                .collect();
            let said = vox_text::offer::said(
                &vox_text::offer::name(None, &crate::node::link::b32_encode(&member)),
                why.contains(&OfferWhy::Joined),
                why.contains(&OfferWhy::TrustsYou),
                &names,
            );
            Offer {
                member,
                rooms: in_rooms,
                said,
                why,
                trusted_by,
            }
        })
        .collect()
}

/// Most offers carried on the wire at once: a reply or a snapshot with more is malformed.
pub const MAX_OFFERS: usize = 1024;

/// Write `offers` as `[[member, [room..], [why..], [trusted_by..]], ..]`.
pub fn put_offers(e: &mut Encoder, offers: &[Offer]) {
    e.array(offers.len());
    for o in offers {
        e.array(5).bytes(&o.member).array(o.rooms.len());
        for r in &o.rooms {
            e.array(2).bytes(&r.id).text(&r.name);
        }
        e.text(&o.said);
        e.array(o.why.len());
        for w in &o.why {
            e.uint(match w {
                OfferWhy::Joined => 0,
                OfferWhy::TrustsYou => 1,
            });
        }
        e.array(o.trusted_by.len());
        for t in &o.trusted_by {
            e.bytes(t);
        }
    }
}

/// Read what [`put_offers`] wrote.
///
/// # Errors
/// Anything else, or more than [`MAX_OFFERS`].
pub fn read_offers(d: &mut Decoder<'_>) -> Result<Vec<Offer>> {
    let bad = Error::MalformedIpc;
    let digest = |d: &mut Decoder<'_>| -> Result<Digest32> {
        Digest32::try_from(d.bytes().map_err(|_| bad("offer digest"))?)
            .map_err(|_| bad("offer digest length"))
    };
    let n = d.array().map_err(|_| bad("offers"))?;
    if n > MAX_OFFERS {
        return Err(Error::SizeLimitExceeded("offers"));
    }
    let mut out = Vec::new();
    for _ in 0..n {
        if d.array().map_err(|_| bad("offer"))? != 5 {
            return Err(bad("offer arity"));
        }
        let member = digest(d)?;
        let mut rooms = Vec::new();
        for _ in 0..d.array().map_err(|_| bad("offer rooms"))? {
            if d.array().map_err(|_| bad("offer room"))? != 2 {
                return Err(bad("offer room arity"));
            }
            let id = digest(d)?;
            let name = d.text().map_err(|_| bad("offer room name"))?.to_owned();
            rooms.push(OfferRoom { id, name });
        }
        let said = d.text().map_err(|_| bad("offer said"))?.to_owned();
        let mut why = Vec::new();
        for _ in 0..d.array().map_err(|_| bad("offer why"))? {
            why.push(match d.uint().map_err(|_| bad("offer why"))? {
                0 => OfferWhy::Joined,
                1 => OfferWhy::TrustsYou,
                _ => return Err(bad("offer why")),
            });
        }
        let mut trusted_by = Vec::new();
        for _ in 0..d.array().map_err(|_| bad("offer trusted by"))? {
            trusted_by.push(digest(d)?);
        }
        out.push(Offer {
            member,
            rooms,
            said,
            why,
            trusted_by,
        });
    }
    Ok(out)
}
