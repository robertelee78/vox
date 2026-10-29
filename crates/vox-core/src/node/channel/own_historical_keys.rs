//! Sealed self-author receiver states for historical epochs. They never replace a live receiver.
//! A room purge removes this namespace with the rest of its key material.
use super::entry_store::session_tree;
use super::*;

const KIND: SegmentKind = SegmentKind::OwnHistoricalKeys;
const MAX_BYTES: usize = crate::node::pairwise_stream::MAX_PAIRWISE_FRAME;

/// One bounded pass over the signed own feed per stored key. The cursor is deliberately
/// volatile: after a restart it rechecks every candidate instead of trusting an old retention
/// verdict. A completed pass sleeps until the feed, policy, or retained bodies change.
#[derive(Clone, Default)]
pub(super) struct Retirement {
    pub(super) after: Option<[u8; 64]>,
    pub(super) current: Option<([u8; 64], u64, u64)>,
    pub(super) complete: bool,
    pub(super) head: u64,
    pub(super) epoch: u64,
    pub(super) retention: (u64, u64),
    pub(super) entry_generation: u64,
    pub(super) wake_at: Option<u64>,
}

impl Retirement {
    pub(super) fn reset(&mut self) {
        self.after = None;
        self.current = None;
        self.complete = false;
        self.wake_at = None;
    }

    pub(super) fn wait_until(&mut self, at: u64) {
        self.wake_at = Some(self.wake_at.map_or(at, |prior| prior.min(at)));
    }
}

pub(super) fn first_after(
    snapshot: &crate::node::store::Snapshot,
    sek: &Sek,
    room: &Digest32,
    after: Option<[u8; 64]>,
) -> Result<Option<([u8; 64], u64)>> {
    let Some(sealed) = snapshot.get_segment_bounded(room, KIND, 0, 128)? else {
        return Ok(None);
    };
    let h = Header::decode(&open_segment(sek, KIND, 0, &sealed)?)?;
    let next =
        session_tree::Read::snapshot(snapshot, sek, room, KIND).first_after(h.root, after)?;
    if let Some((_, id)) = next {
        if id == 0 || id >= h.next {
            return Err(bad());
        }
    }
    Ok(next)
}

/// Called only after a bounded scan found no retained or owed own content for this key.
pub(super) fn retire(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    key: [u8; 64],
    id: u64,
) -> Result<()> {
    let sealed = batch
        .get_segment_bounded(room, KIND, 0, 128)?
        .ok_or_else(bad)?;
    let mut h = Header::decode(&open_segment(sek, KIND, 0, &sealed)?)?;
    if id == 0
        || id >= h.next
        || h.count == 0
        || session_tree::Read::batch(batch, sek, room, KIND).find(h.root, &key)? != Some(id)
    {
        return Err(bad());
    }
    let mut tree = session_tree::Write::new(batch, sek, room, KIND, h.next)?;
    h.root = tree.set(h.root, key, None)?;
    h.next = tree.next_page();
    batch.delete_segment(room, KIND, id)?;
    h.count -= 1;
    h.seal(batch, sek, room)
}

fn bad() -> Error {
    Error::MalformedAtRest("own historical key index")
}
fn key(epoch: u64, chain: u64) -> [u8; 64] {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&epoch.to_be_bytes());
    key[8..16].copy_from_slice(&chain.to_be_bytes());
    key
}
struct Header {
    root: u64,
    next: u64,
    count: usize,
}
impl Header {
    fn empty() -> Self {
        Self {
            root: 0,
            next: 1,
            count: 0,
        }
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 4 || d.uint()? != 1 {
            return Err(bad());
        }
        let h = Self {
            root: d.uint()?,
            next: d.uint()?,
            count: usize::try_from(d.uint()?).map_err(|_| bad())?,
        };
        d.finish()?;
        if h.next == 0 || h.root >= h.next || (h.root == 0) != (h.count == 0) {
            return Err(bad());
        }
        Ok(h)
    }
    fn seal(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        sek: &Sek,
        room: &Digest32,
    ) -> Result<()> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(1)
            .uint(self.root)
            .uint(self.next)
            .uint(self.count as u64);
        batch.put_segment(room, KIND, 0, &seal_segment(sek, KIND, 0, &e.finish())?)
    }
}
fn decode_state(
    sealed: &SealedSegment,
    id: u64,
    sek: &Sek,
    room: &Digest32,
    root: &CompositePublicKey,
    author: &Digest32,
    (epoch, chain): (u64, u64),
) -> Result<ReceiverChain> {
    let state = open_segment(sek, KIND, id, sealed)?;
    let receiver = ReceiverChain::from_state(&state)?;
    if root.fingerprint() != *author || !receiver.bound_to(room, epoch, author, chain) {
        return Err(bad());
    }
    Ok(receiver)
}

/// Load one exact key without materializing the index; absence is not a claim that a donor has it.
pub(super) fn lookup(
    snapshot: &crate::node::store::Snapshot,
    sek: &Sek,
    room: &Digest32,
    root: &CompositePublicKey,
    author: &Digest32,
    epoch: u64,
    chain: u64,
) -> Result<Option<ReceiverChain>> {
    let Some(sealed) = snapshot.get_segment_bounded(room, KIND, 0, 128)? else {
        return Ok(None);
    };
    let h = Header::decode(&open_segment(sek, KIND, 0, &sealed)?)?;
    let Some(id) =
        session_tree::Read::snapshot(snapshot, sek, room, KIND).find(h.root, &key(epoch, chain))?
    else {
        return Ok(None);
    };
    if id == 0 || id >= h.next {
        return Err(bad());
    }
    let sealed = snapshot
        .get_segment_bounded(room, KIND, id, MAX_BYTES)?
        .ok_or_else(bad)?;
    Ok(Some(decode_state(
        &sealed,
        id,
        sek,
        room,
        root,
        author,
        (epoch, chain),
    )?))
}

pub(super) fn lookup_batch(
    batch: &crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    root: &CompositePublicKey,
    author: &Digest32,
    epoch: u64,
    chain: u64,
) -> Result<Option<ReceiverChain>> {
    let Some(sealed) = batch.get_segment_bounded(room, KIND, 0, 128)? else {
        return Ok(None);
    };
    let h = Header::decode(&open_segment(sek, KIND, 0, &sealed)?)?;
    let Some(id) =
        session_tree::Read::batch(batch, sek, room, KIND).find(h.root, &key(epoch, chain))?
    else {
        return Ok(None);
    };
    if id == 0 || id >= h.next {
        return Err(bad());
    }
    let sealed = batch
        .get_segment_bounded(room, KIND, id, MAX_BYTES)?
        .ok_or_else(bad)?;
    Ok(Some(decode_state(
        &sealed,
        id,
        sek,
        room,
        root,
        author,
        (epoch, chain),
    )?))
}

/// Retain the earlier verified floor without evicting a potentially needed key. The sealed tree
/// performs bounded page operations without a fixed key-count cap; room purge removes its rows.
pub(super) fn put(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    root: &CompositePublicKey,
    author: &Digest32,
    release: &Skdm,
) -> Result<bool> {
    let epoch = release.body.epoch;
    let chain = release.body.chain_id;
    release.verify(root, room, epoch)?;
    if release.body.author_id != *author {
        return Err(bad());
    }
    let mut h = match batch.get_segment_bounded(room, KIND, 0, 128)? {
        Some(sealed) => Header::decode(&open_segment(sek, KIND, 0, &sealed)?)?,
        None => Header::empty(),
    };
    let k = key(epoch, chain);
    let previous = session_tree::Read::batch(batch, sek, room, KIND).find(h.root, &k)?;
    if let Some(id) = previous {
        if id == 0 || id >= h.next {
            return Err(bad());
        }
        let sealed = batch
            .get_segment_bounded(room, KIND, id, MAX_BYTES)?
            .ok_or_else(bad)?;
        let existing = decode_state(&sealed, id, sek, room, root, author, (epoch, chain))?;
        let incoming = ReceiverChain::from_skdm(release, root, room, epoch)?;
        let mut check = ReceiverChain::from_state(&existing.to_state())?;
        // Also validates the same sender signing key and complete chain binding.
        if !check.retain_history_release(&incoming)? {
            return Ok(false);
        }
    }
    // The release is verified above; persist only the resulting receiver state.
    let state = ReceiverChain::from_skdm(release, root, room, epoch)?.to_state();
    if state.len() > MAX_BYTES {
        return Err(Error::SizeLimitExceeded("own historical receiver state"));
    }
    let id = h.next;
    h.next = h.next.checked_add(1).ok_or_else(bad)?;
    batch.put_segment(room, KIND, id, &seal_segment(sek, KIND, id, &state)?)?;
    {
        let mut tree = session_tree::Write::new(batch, sek, room, KIND, h.next)?;
        h.root = tree.set(h.root, k, Some(id))?;
        h.next = tree.next_page();
    }
    if let Some(old) = previous {
        batch.delete_segment(room, KIND, old)?;
    } else {
        h.count = h
            .count
            .checked_add(1)
            .ok_or(Error::SizeLimitExceeded("own historical key index"))?;
    }
    h.seal(batch, sek, room)?;
    Ok(true)
}
