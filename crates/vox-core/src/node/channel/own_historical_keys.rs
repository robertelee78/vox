//! Bounded, sealed original self-author releases for historical epochs. They never replace a
//! live receiver. A room purge removes this namespace with the rest of its key material.
use super::entry_store::session_tree;
use super::*;

const KIND: SegmentKind = SegmentKind::OwnHistoricalKeys;
const MAX_BYTES: usize = crate::node::pairwise_stream::MAX_PAIRWISE_FRAME;

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
fn decode_release(
    sealed: &SealedSegment,
    id: u64,
    sek: &Sek,
    room: &Digest32,
    root: &CompositePublicKey,
    author: &Digest32,
    epoch: u64,
    chain: u64,
) -> Result<Skdm> {
    let wire = open_segment(sek, KIND, id, sealed)?;
    let release = Skdm::from_wire(&wire)?;
    release.verify(root, room, epoch)?;
    if release.body.author_id != *author || release.body.chain_id != chain {
        return Err(bad());
    }
    Ok(release)
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
    let release = decode_release(&sealed, id, sek, room, root, author, epoch, chain)?;
    Ok(Some(ReceiverChain::from_skdm(&release, root, room, epoch)?))
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
    let release = decode_release(&sealed, id, sek, room, root, author, epoch, chain)?;
    Ok(Some(ReceiverChain::from_skdm(&release, root, room, epoch)?))
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
        let prior = decode_release(&sealed, id, sek, room, root, author, epoch, chain)?;
        let existing = ReceiverChain::from_skdm(&prior, root, room, epoch)?;
        let incoming = ReceiverChain::from_skdm(release, root, room, epoch)?;
        let mut check = ReceiverChain::from_state(&existing.to_state())?;
        // Also validates the same sender signing key and complete chain binding.
        if !check.retain_history_release(&incoming)? {
            return Ok(false);
        }
    }
    let wire = Zeroizing::new(release.to_wire());
    if wire.len() > MAX_BYTES {
        return Err(Error::SizeLimitExceeded("own historical release"));
    }
    let id = h.next;
    h.next = h.next.checked_add(1).ok_or_else(bad)?;
    batch.put_segment(room, KIND, id, &seal_segment(sek, KIND, id, &wire)?)?;
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
