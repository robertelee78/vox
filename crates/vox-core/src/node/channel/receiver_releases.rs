//! Exact root-signed releases retained independently of history publication. Receiver state
//! remains the authority to use a release; this index alone grants neither trust nor a key.

use super::entry_store::session_tree;
use super::*;

const KIND: SegmentKind = SegmentKind::ReceiverReleases;
const HEADER: u64 = 0;
const HEADER_BYTES: usize = 256;
const DESCRIPTOR_BYTES: usize = 256;
// The existing authenticated pairwise frame envelope also bounds an original signed release.
const RELEASE_BYTES: usize = crate::node::pairwise_stream::MAX_PAIRWISE_FRAME;
pub(super) const CLEANUP_PENDING: &str = "received key releases await bounded cleanup";
type ReleaseKey = [u8; 64];

#[derive(Default)]
struct Header {
    root: u64,
    next: u64,
    count: usize,
    cleanup: bool,
    retry_owed: bool,
    after: Option<ReleaseKey>,
}
impl Header {
    fn load(batch: &crate::node::store::Batch<'_>, sek: &Sek, room: &Digest32) -> Result<Self> {
        let Some(sealed) = batch.get_segment_bounded(room, KIND, HEADER, HEADER_BYTES)? else {
            return Ok(Self {
                next: 1,
                ..Self::default()
            });
        };
        let bytes = open_segment(sek, KIND, HEADER, &sealed)?;
        Self::decode(&bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 7 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("receiver release index version"));
        }
        let root = d.uint()?;
        let next = d.uint()?;
        let count = usize::try_from(d.uint()?)
            .map_err(|_| Error::MalformedAtRest("receiver release count"))?;
        let cleanup = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedAtRest("receiver release cleanup flag")),
        };
        let retry_owed = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedAtRest("receiver release retry flag")),
        };
        let after = match d.bytes()? {
            [] => None,
            key => Some(
                key.try_into()
                    .map_err(|_| Error::MalformedAtRest("receiver release cursor"))?,
            ),
        };
        d.finish()?;
        if (root == 0) != (count == 0)
            || next == 0
            || root >= next
            || count > MAX_RECEIVER_CHAINS
            || (!cleanup && after.is_some())
        {
            return Err(Error::MalformedAtRest("receiver release index bounds"));
        }
        Ok(Self {
            root,
            next,
            count,
            cleanup,
            retry_owed,
            after,
        })
    }
    fn seal(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        sek: &Sek,
        room: &Digest32,
    ) -> Result<()> {
        let mut e = Encoder::new();
        e.array(7)
            .uint(1)
            .uint(self.root)
            .uint(self.next)
            .uint(self.count as u64)
            .uint(u64::from(self.cleanup))
            .uint(u64::from(self.retry_owed))
            .bytes(self.after.as_ref().map_or(&[][..], |key| &key[..]));
        let sealed = seal_segment(sek, KIND, HEADER, &e.finish())?;
        batch.put_segment(room, KIND, HEADER, &sealed)
    }
}
fn key(author: &Digest32, epoch: u64, chain: u64) -> ReleaseKey {
    let mut key = [0; 64];
    key[..32].copy_from_slice(author);
    key[32..40].copy_from_slice(&epoch.to_be_bytes());
    key[40..48].copy_from_slice(&chain.to_be_bytes());
    key
}
fn slot(key: &ReleaseKey) -> Result<(Digest32, u64, u64)> {
    if key[48..].iter().any(|byte| *byte != 0) {
        return Err(Error::MalformedAtRest("receiver release key padding"));
    }
    Ok((
        key[..32]
            .try_into()
            .map_err(|_| Error::MalformedAtRest("receiver release author"))?,
        u64::from_be_bytes(
            key[32..40]
                .try_into()
                .map_err(|_| Error::MalformedAtRest("receiver release epoch"))?,
        ),
        u64::from_be_bytes(
            key[40..48]
                .try_into()
                .map_err(|_| Error::MalformedAtRest("receiver release generation"))?,
        ),
    ))
}

struct Descriptor {
    author: Digest32,
    epoch: u64,
    chain: u64,
    floor: u64,
    digest: Digest32,
    body: u64,
}
impl Descriptor {
    fn load(
        batch: &crate::node::store::Batch<'_>,
        sek: &Sek,
        room: &Digest32,
        header: &Header,
        key: &ReleaseKey,
        id: u64,
    ) -> Result<Self> {
        let sealed = batch
            .get_segment_bounded(room, KIND, id, DESCRIPTOR_BYTES)?
            .ok_or(Error::MalformedAtRest(
                "receiver release descriptor missing",
            ))?;
        let bytes = open_segment(sek, KIND, id, &sealed)?;
        Self::decode(&bytes, header, key, id)
    }
    fn decode(bytes: &[u8], header: &Header, key: &ReleaseKey, id: u64) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 7 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest(
                "receiver release descriptor version",
            ));
        }
        let author = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("receiver release descriptor author"))?;
        let epoch = d.uint()?;
        let chain = d.uint()?;
        let floor = d.uint()?;
        let digest = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("receiver release descriptor digest"))?;
        let body = d.uint()?;
        d.finish()?;
        if self::key(&author, epoch, chain) != *key
            || body == 0
            || body >= header.next
            || body == id
        {
            return Err(Error::MalformedAtRest(
                "receiver release descriptor binding",
            ));
        }
        Ok(Self {
            author,
            epoch,
            chain,
            floor,
            digest,
            body,
        })
    }
    fn current(&self, receiver: Option<&ReceiverChain>) -> bool {
        receiver.is_some_and(|receiver| {
            receiver.epoch() == self.epoch
                && receiver.history_release_binding() == (self.floor, self.digest)
        })
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
            .bytes(&self.author)
            .uint(self.epoch)
            .uint(self.chain)
            .uint(self.floor)
            .bytes(&self.digest)
            .uint(self.body);
        let sealed = seal_segment(sek, KIND, id, &e.finish())?;
        batch.put_segment(room, KIND, id, &sealed)
    }
}

pub(super) enum Remember {
    Unchanged,
    Retained,
    Busy { changed: bool },
}

/// The exact verified release, receiver state and backfill share one transaction. The old
/// receiver is separate: a re-admission must never revive a release revoked before this call.
pub(super) fn remember(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    author_root: &CompositePublicKey,
    release: &Skdm,
    previous: Option<&ReceiverChain>,
    receiver: &ReceiverChain,
) -> Result<Remember> {
    if !receiver.matches_history_release(release) {
        return Ok(Remember::Unchanged);
    }
    let mut header = Header::load(batch, sek, room)?;
    let key = key(
        &release.body.author_id,
        release.body.epoch,
        release.body.chain_id,
    );
    let old = session_tree::Read::batch(batch, sek, room, KIND).find(header.root, &key)?;
    let prior = old
        .map(|id| Descriptor::load(batch, sek, room, &header, &key, id))
        .transpose()?;
    if let Some(prior) = &prior {
        if prior.current(previous) {
            let sealed = batch
                .get_segment_bounded(room, KIND, prior.body, RELEASE_BYTES)?
                .ok_or(Error::MalformedAtRest("receiver release source missing"))?;
            let bytes = open_segment(sek, KIND, prior.body, &sealed)?;
            let stored = Skdm::from_wire(&bytes)?;
            stored.verify(author_root, room, prior.epoch)?;
            if self::key(
                &stored.body.author_id,
                stored.body.epoch,
                stored.body.chain_id,
            ) != key
                || stored.body.iteration != prior.floor
                || crate::hash::sha256(&stored.body.canonical_body()) != prior.digest
            {
                return Err(Error::MalformedAtRest("receiver release source binding"));
            }
            if prior.floor <= release.body.iteration {
                return Ok(Remember::Unchanged);
            }
        }
    } else if header.count >= MAX_RECEIVER_CHAINS {
        let changed = !header.retry_owed;
        if changed {
            header.retry_owed = true;
            header.seal(batch, sek, room)?;
        }
        return Ok(Remember::Busy { changed });
    }
    let wire = release.to_wire();
    if wire.len() > RELEASE_BYTES {
        return Err(Error::SizeLimitExceeded("signed receiver release"));
    }
    let body = header.next;
    let id = body.checked_add(1).ok_or(Error::MalformedAtRest(
        "receiver release allocator exhausted",
    ))?;
    header.next = id.checked_add(1).ok_or(Error::MalformedAtRest(
        "receiver release allocator exhausted",
    ))?;
    let sealed = seal_segment(sek, KIND, body, &wire)?;
    batch.put_segment(room, KIND, body, &sealed)?;
    Descriptor {
        author: release.body.author_id,
        epoch: release.body.epoch,
        chain: release.body.chain_id,
        floor: release.body.iteration,
        digest: crate::hash::sha256(&release.body.canonical_body()),
        body,
    }
    .seal(batch, sek, room, id)?;
    {
        let mut tree = session_tree::Write::new(batch, sek, room, KIND, header.next)?;
        header.root = tree.set(header.root, key, Some(id))?;
        header.next = tree.next_page();
    }
    if let Some(prior) = prior {
        batch.delete_segment(room, KIND, prior.body)?;
        batch.delete_segment(
            room,
            KIND,
            old.ok_or(Error::MalformedAtRest("receiver release locator lost"))?,
        )?;
    } else {
        header.count += 1;
    }
    header.seal(batch, sek, room)?;
    Ok(Remember::Retained)
}

/// The caller removes receiver access in this same Batch. One durable cursor, rather than
/// thousands of synchronous tree deletions, retains the physical cleanup obligation.
pub(super) fn retire(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
) -> Result<()> {
    let mut header = Header::load(batch, sek, room)?;
    if header.count == 0 {
        return Ok(());
    }
    header.cleanup = true;
    header.after = None;
    header.seal(batch, sek, room)
}

/// Select only the next cleanup receiver. Its binding, never a receiver map or key, crosses
/// publication ownership; the native transaction still validates the exact descriptor.
pub(super) fn cleanup_receiver(
    store: &Store,
    sek: &Sek,
    room: &Digest32,
) -> Result<Option<(Digest32, u64)>> {
    let snapshot = store.snapshot()?;
    let Some(sealed) = snapshot.get_segment_bounded(room, KIND, HEADER, HEADER_BYTES)? else {
        return Ok(None);
    };
    let header = Header::decode(&open_segment(sek, KIND, HEADER, &sealed)?)?;
    if !header.cleanup {
        return Ok(None);
    }
    session_tree::Read::snapshot(&snapshot, sek, room, KIND)
        .first_after(header.root, header.after)?
        .map(|(key, _)| slot(&key).map(|(author, _, chain)| (author, chain)))
        .transpose()
}

/// Same bounded cleanup, with only committed receiver metadata crossing a worker boundary.
pub(super) fn advance_current(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    current: impl Fn(&Digest32, u64, u64, (u64, Digest32)) -> Result<bool>,
) -> Result<Option<(bool, bool)>> {
    let mut header = Header::load(batch, sek, room)?;
    if !header.cleanup {
        return Ok(None);
    }
    let mut retry_ready = false;
    match session_tree::Read::batch(batch, sek, room, KIND)
        .first_after(header.root, header.after)?
    {
        None => {
            // A stale descriptor may be replaced before this scan reaches it. A full index
            // of current receivers is not corrupt: leave the owed release parked until
            // receiver retirement frees a slot, without rescheduling this scan.
            header.cleanup = false;
            header.after = None;
        }
        Some((key, id)) => {
            let descriptor = Descriptor::load(batch, sek, room, &header, &key, id)?;
            if !current(
                &descriptor.author,
                descriptor.chain,
                descriptor.epoch,
                (descriptor.floor, descriptor.digest),
            )? {
                {
                    let mut tree = session_tree::Write::new(batch, sek, room, KIND, header.next)?;
                    header.root = tree.set(header.root, key, None)?;
                    header.next = tree.next_page();
                }
                batch.delete_segment(room, KIND, descriptor.body)?;
                batch.delete_segment(room, KIND, id)?;
                retry_ready = std::mem::take(&mut header.retry_owed);
                header.count = header
                    .count
                    .checked_sub(1)
                    .ok_or(Error::MalformedAtRest("receiver release count underflow"))?;
            }
            header.after = Some(key);
        }
    }
    header.seal(batch, sek, room)?;
    Ok(Some((header.cleanup, retry_ready)))
}

/// Exact serving lookup. Check the currently installed receiver before even opening an
/// auxiliary artifact, and validate its descriptor before opening any retained chain key.
pub(super) fn lookup(
    store: &Store,
    sek: &Sek,
    room: &Digest32,
    receiver: &ReceiverChain,
    root: &CompositePublicKey,
    needed_iteration: u64,
) -> Result<Option<Skdm>> {
    let snapshot = store.snapshot()?;
    let Some(sealed) = snapshot.get_segment_bounded(room, KIND, HEADER, HEADER_BYTES)? else {
        return Ok(None);
    };
    let header = Header::decode(&open_segment(sek, KIND, HEADER, &sealed)?)?;
    let key = key(&receiver.author_id(), receiver.epoch(), receiver.chain_id());
    let Some(id) =
        session_tree::Read::snapshot(&snapshot, sek, room, KIND).find(header.root, &key)?
    else {
        return Ok(None);
    };
    let sealed = snapshot
        .get_segment_bounded(room, KIND, id, DESCRIPTOR_BYTES)?
        .ok_or(Error::MalformedAtRest(
            "receiver release descriptor missing",
        ))?;
    let descriptor = Descriptor::decode(&open_segment(sek, KIND, id, &sealed)?, &header, &key, id)?;
    if !descriptor.current(Some(receiver)) || descriptor.floor > needed_iteration {
        return Ok(None);
    }
    let sealed = snapshot
        .get_segment_bounded(room, KIND, descriptor.body, RELEASE_BYTES)?
        .ok_or(Error::MalformedAtRest("receiver release source missing"))?;
    let bytes = open_segment(sek, KIND, descriptor.body, &sealed)?;
    let release = Skdm::from_wire(&bytes)?;
    release.verify(root, room, receiver.epoch())?;
    if !receiver.matches_history_release(&release)
        || crate::hash::sha256(&release.body.canonical_body()) != descriptor.digest
    {
        return Err(Error::MalformedAtRest("receiver release source binding"));
    }
    Ok(Some(release))
}
