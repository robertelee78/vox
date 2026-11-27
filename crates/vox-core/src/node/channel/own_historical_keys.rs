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
    /// Per stored key, the own position through which the scan found nothing that keeps it.
    /// Each position it passed is passed for good while the epoch and the retention policy
    /// stand: another epoch or kind, a body expired under both policies, or a held body of
    /// another chain. So a new pass (a commit, an own post, a wake) resumes each key here;
    /// only `reset` clears it.
    pub(super) checked: std::collections::BTreeMap<[u8; 64], u64>,
}

impl Retirement {
    /// Everything again from position 1: the epoch or the retention policy changed.
    pub(super) fn reset(&mut self) {
        self.new_pass();
        self.checked.clear();
    }

    /// Every key again, each from where it was checked through.
    pub(super) fn new_pass(&mut self) {
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
