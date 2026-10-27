//! Own-author receiver overrides. The sealed base map remains readable; a matching sealed
//! basis makes these records authoritative until a whole-map rewrite incorporates them.
use super::entry_store::session_tree;
use super::*;

const KIND: SegmentKind = SegmentKind::ReceiverStates;
const HEADER_BYTES: usize = 512;
const RECORD_BYTES: usize = 256;
const STATE_BYTES: usize = crate::node::pairwise_stream::MAX_PAIRWISE_FRAME;
type Key = [u8; 64];
pub(super) const CLEANUP_PENDING: &str = receiver_releases::CLEANUP_PENDING;

pub(super) struct Persistence {
    nonce: [u8; 16],
    normal: u64,
    drive: u64,
    pub(super) base: Digest32,
}
impl Persistence {
    pub(super) fn new(base: Digest32) -> Result<Self> {
        Ok(Self {
            nonce: crate::identity::rng::random_array()?,
            normal: 0,
            drive: 0,
            base,
        })
    }
    pub(super) fn advance_normal(&mut self) -> Result<()> {
        self.normal = self.normal.checked_add(1).ok_or(invalid())?;
        Ok(())
    }
    pub(super) fn advance_drive(&mut self) -> Result<()> {
        self.drive = self.drive.checked_add(1).ok_or(invalid())?;
        Ok(())
    }
    pub(super) fn next_normal(&self) -> Result<Stamp> {
        Ok(Stamp(
            self.nonce,
            self.normal.checked_add(1).ok_or(invalid())?,
        ))
    }
    pub(super) fn normal(&self) -> Stamp {
        Stamp(self.nonce, self.normal)
    }
    pub(super) fn drive(&self) -> Stamp {
        Stamp(self.nonce, self.drive)
    }
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Stamp([u8; 16], u64);
impl Stamp {
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 2 {
            return Err(invalid());
        }
        Ok(Self(
            d.bytes()?.try_into().map_err(|_| invalid())?,
            d.uint()?,
        ))
    }
    fn encode(self, e: &mut Encoder) {
        e.array(2).bytes(&self.0).uint(self.1);
    }
}
fn invalid() -> Error {
    Error::MalformedAtRest("own receiver overlay binding")
}
pub(super) fn digest(segment: Option<&SealedSegment>) -> Digest32 {
    match segment {
        Some(segment) => crate::hash::sha256_concat(&[&segment.nonce, &segment.ciphertext]),
        None => crate::hash::sha256(b"vox/receivers/absent/v1"),
    }
}
#[derive(Default)]
struct Header {
    root: u64,
    next: u64,
    count: usize,
    generation: u64,
    basis: Option<Digest32>,
    cleanup: bool,
    retry_owed: bool,
    after: Option<Key>,
    normal: Stamp,
    drive: Stamp,
}
impl Header {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 11 || d.uint()? != 1 {
            return Err(invalid());
        }
        let root = d.uint()?;
        let next = d.uint()?;
        let count = usize::try_from(d.uint()?).map_err(|_| invalid())?;
        let generation = d.uint()?;
        let basis = match d.bytes()? {
            [] => None,
            b => Some(b.try_into().map_err(|_| invalid())?),
        };
        let cleanup = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(invalid()),
        };
        let retry_owed = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(invalid()),
        };
        let after = match d.bytes()? {
            [] => None,
            b => Some(b.try_into().map_err(|_| invalid())?),
        };
        let normal = Stamp::decode(&mut d)?;
        let drive = Stamp::decode(&mut d)?;
        d.finish()?;
        if next == 0
            || root >= next
            || (root == 0) != (count == 0)
            || count > MAX_RECEIVER_CHAINS
            || (!cleanup && (after.is_some() || retry_owed))
            || (basis.is_none() && (generation != 0 || count != 0))
        {
            return Err(invalid());
        }
        Ok(Self {
            root,
            next,
            count,
            generation,
            basis,
            cleanup,
            retry_owed,
            after,
            normal,
            drive,
        })
    }
    fn load(batch: &crate::node::store::Batch<'_>, sek: &Sek, room: &Digest32) -> Result<Self> {
        match batch.get_segment_bounded(room, KIND, 0, HEADER_BYTES)? {
            Some(sealed) => Self::decode(&open_segment(sek, KIND, 0, &sealed)?),
            None => Ok(Self {
                next: 1,
                ..Self::default()
            }),
        }
    }
    fn seal(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        sek: &Sek,
        room: &Digest32,
    ) -> Result<()> {
        let mut e = Encoder::new();
        e.array(11)
            .uint(1)
            .uint(self.root)
            .uint(self.next)
            .uint(self.count as u64)
            .uint(self.generation)
            .bytes(self.basis.as_ref().map_or(&[][..], |b| &b[..]))
            .uint(u64::from(self.cleanup))
            .uint(u64::from(self.retry_owed))
            .bytes(self.after.as_ref().map_or(&[][..], |b| &b[..]));
        self.normal.encode(&mut e);
        self.drive.encode(&mut e);
        batch.put_segment(room, KIND, 0, &seal_segment(sek, KIND, 0, &e.finish())?)
    }
}
fn key(chain: u64) -> Key {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&chain.to_be_bytes());
    key
}
struct Record {
    generation: u64,
    basis: Digest32,
    author: Digest32,
    epoch: u64,
    chain: u64,
    body: u64,
}
impl Record {
    fn decode(bytes: &[u8], h: &Header, k: &Key, id: u64) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 7 || d.uint()? != 1 {
            return Err(invalid());
        }
        let record = Self {
            generation: d.uint()?,
            basis: d.bytes()?.try_into().map_err(|_| invalid())?,
            author: d.bytes()?.try_into().map_err(|_| invalid())?,
            epoch: d.uint()?,
            chain: d.uint()?,
            body: d.uint()?,
        };
        d.finish()?;
        if key(record.chain) != *k
            || record.body == 0
            || record.body >= h.next
            || record.body == id
            || record.generation > h.generation
            || (record.generation == h.generation && Some(record.basis) != h.basis)
        {
            return Err(invalid());
        }
        Ok(record)
    }
    fn seal(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        sek: &Sek,
        room: &Digest32,
        id: u64,
    ) -> Result<()> {
        let mut e = Encoder::new();
        e.array(7)
            .uint(1)
            .uint(self.generation)
            .bytes(&self.basis)
            .bytes(&self.author)
            .uint(self.epoch)
            .uint(self.chain)
            .uint(self.body);
        batch.put_segment(room, KIND, id, &seal_segment(sek, KIND, id, &e.finish())?)
    }
    fn load(
        batch: &crate::node::store::Batch<'_>,
        sek: &Sek,
        room: &Digest32,
        h: &Header,
        k: &Key,
        id: u64,
    ) -> Result<Self> {
        let sealed = batch
            .get_segment_bounded(room, KIND, id, RECORD_BYTES)?
            .ok_or(invalid())?;
        Self::decode(&open_segment(sek, KIND, id, &sealed)?, h, k, id)
    }
}

/// Startup already opened the legacy base once. Only one bounded override body is resident
/// while merging; the merged map, including override-created slots, retains the existing cap.
pub(super) fn merge(
    snapshot: &crate::node::store::Snapshot,
    sek: &Sek,
    room: &Digest32,
    me: &Digest32,
    epoch: u64,
    base: Digest32,
    receivers: &mut BTreeMap<(Digest32, u64), ReceiverChain>,
) -> Result<()> {
    let Some(sealed) = snapshot.get_segment_bounded(room, KIND, 0, HEADER_BYTES)? else {
        return Ok(());
    };
    let h = Header::decode(&open_segment(sek, KIND, 0, &sealed)?)?;
    if h.basis.is_some_and(|basis| basis != base) {
        return Err(invalid());
    }
    let tree = session_tree::Read::snapshot(snapshot, sek, room, KIND);
    let mut after = None;
    let mut seen = 0;
    while let Some((k, id)) = tree.first_after(h.root, after)? {
        seen += 1;
        if seen > MAX_RECEIVER_CHAINS {
            return Err(invalid());
        }
        let sealed = snapshot
            .get_segment_bounded(room, KIND, id, RECORD_BYTES)?
            .ok_or(invalid())?;
        let record = Record::decode(&open_segment(sek, KIND, id, &sealed)?, &h, &k, id)?;
        if record.generation == h.generation {
            if record.author != *me || record.epoch != epoch {
                return Err(invalid());
            }
            let sealed = snapshot
                .get_segment_bounded(room, KIND, record.body, STATE_BYTES)?
                .ok_or(invalid())?;
            let state = open_segment(sek, KIND, record.body, &sealed)?;
            let receiver = ReceiverChain::from_state(&state)?;
            if !receiver.bound_to(room, epoch, me, record.chain) {
                return Err(invalid());
            }
            let slot = (*me, record.chain);
            if !receivers.contains_key(&slot) && receivers.len() >= MAX_RECEIVER_CHAINS {
                return Err(invalid());
            }
            receivers.insert(slot, receiver);
        }
        after = Some(k);
    }
    if seen != h.count {
        return Err(invalid());
    }
    Ok(())
}

/// Full writers incorporate the already-merged map, then supersede old overrides atomically.
pub(super) fn rewrite(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    segment: &SealedSegment,
    stamp: Stamp,
) -> Result<()> {
    let mut h = Header::load(batch, sek, room)?;
    h.generation = h.generation.checked_add(1).ok_or(invalid())?;
    h.basis = Some(digest(Some(segment)));
    h.normal = stamp;
    h.cleanup = h.count > 0;
    h.after = None;
    batch.put_segment(room, SegmentKind::KeyMaterial, SEG_RECEIVERS, segment)?;
    h.seal(batch, sek, room)
}
pub(super) fn normal_dirty(
    batch: &crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    stamp: Stamp,
) -> Result<bool> {
    Ok(stamp.1 != 0 && Header::load(batch, sek, room)?.normal != stamp)
}
pub(super) fn drive_dirty(
    batch: &crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    stamp: Stamp,
) -> Result<bool> {
    Ok(stamp.1 != 0 && Header::load(batch, sek, room)?.drive != stamp)
}
pub(super) fn wrote_drive(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    stamp: Stamp,
) -> Result<()> {
    let mut h = Header::load(batch, sek, room)?;
    h.drive = stamp;
    h.seal(batch, sek, room)
}

/// One own slot, original release and backfill cursor share the caller's transaction. No
/// normal receiver-map clone/serialization is required for this install.
pub(super) enum Put {
    Stored,
    Busy { changed: bool },
}

pub(super) fn put(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    me: &Digest32,
    epoch: u64,
    base: Digest32,
    receiver: &ReceiverChain,
) -> Result<Put> {
    if !receiver.bound_to(room, epoch, me, receiver.chain_id()) {
        return Err(invalid());
    }
    let mut h = Header::load(batch, sek, room)?;
    let basis = *h.basis.get_or_insert(base);
    let k = key(receiver.chain_id());
    let prior = session_tree::Read::batch(batch, sek, room, KIND).find(h.root, &k)?;
    if prior.is_none() && h.count >= MAX_RECEIVER_CHAINS {
        if !h.cleanup {
            return Err(invalid());
        }
        let changed = !h.retry_owed;
        if changed {
            h.retry_owed = true;
            h.seal(batch, sek, room)?;
        }
        return Ok(Put::Busy { changed });
    }
    let state = receiver.to_state();
    if state.len() > STATE_BYTES {
        return Err(Error::SizeLimitExceeded("own receiver state"));
    }
    let old = prior
        .map(|id| Record::load(batch, sek, room, &h, &k, id))
        .transpose()?;
    let body = h.next;
    let id = body.checked_add(1).ok_or(invalid())?;
    h.next = id.checked_add(1).ok_or(invalid())?;
    batch.put_segment(room, KIND, body, &seal_segment(sek, KIND, body, &state)?)?;
    Record {
        generation: h.generation,
        basis,
        author: *me,
        epoch,
        chain: receiver.chain_id(),
        body,
    }
    .seal(batch, sek, room, id)?;
    {
        let mut tree = session_tree::Write::new(batch, sek, room, KIND, h.next)?;
        h.root = tree.set(h.root, k, Some(id))?;
        h.next = tree.next_page();
    }
    if let Some(old) = old {
        batch.delete_segment(room, KIND, old.body)?;
        batch.delete_segment(room, KIND, prior.ok_or(invalid())?)?;
    } else {
        h.count += 1;
    }
    h.seal(batch, sek, room)?;
    Ok(Put::Stored)
}

/// One metadata-only stale-record deletion. A current record is never dropped as cleanup.
pub(super) fn advance(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
) -> Result<Option<(bool, bool)>> {
    let mut h = Header::load(batch, sek, room)?;
    if !h.cleanup {
        return Ok(None);
    }
    let mut retry_ready = false;
    match session_tree::Read::batch(batch, sek, room, KIND).first_after(h.root, h.after)? {
        None => {
            if h.retry_owed {
                return Err(invalid());
            }
            h.cleanup = false;
            h.after = None;
        }
        Some((k, id)) => {
            let record = Record::load(batch, sek, room, &h, &k, id)?;
            if record.generation < h.generation {
                {
                    let mut tree = session_tree::Write::new(batch, sek, room, KIND, h.next)?;
                    h.root = tree.set(h.root, k, None)?;
                    h.next = tree.next_page();
                }
                batch.delete_segment(room, KIND, record.body)?;
                batch.delete_segment(room, KIND, id)?;
                h.count = h.count.checked_sub(1).ok_or(invalid())?;
                retry_ready = std::mem::take(&mut h.retry_owed);
            }
            h.after = Some(k);
        }
    }
    h.seal(batch, sek, room)?;
    Ok(Some((h.cleanup, retry_ready)))
}

/// Scalar only: keep an already-sealed cleanup cursor owed when the release GC used this turn.
pub(super) fn pending(
    batch: &crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
) -> Result<bool> {
    Ok(Header::load(batch, sek, room)?.cleanup)
}
