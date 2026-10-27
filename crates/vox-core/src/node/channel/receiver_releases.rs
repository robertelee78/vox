//! Exact root-signed releases retained independently of history publication. Receiver state
//! remains the authority to use a release; this index alone grants neither trust nor a key.

use super::entry_store::session_tree;
use super::*;

const KIND: SegmentKind = SegmentKind::ReceiverReleases;
const HEADER: u64 = 0;
const HEADER_BYTES: usize = 256;
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
        let mut d = Decoder::new(&bytes);
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
            || (!cleanup && (after.is_some() || retry_owed))
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

pub(super) enum Remember {
    Unchanged,
    Retained,
    Busy,
}

/// Called only with the already verified release being installed. Original bytes, receiver
/// state and backfill are committed by the caller in one Batch. No live key map is enlarged.
pub(super) fn remember(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    author_root: &CompositePublicKey,
    release: &Skdm,
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
    if let Some(id) = old {
        let sealed = batch
            .get_segment_bounded(room, KIND, id, RELEASE_BYTES)?
            .ok_or(Error::MalformedAtRest("receiver release source missing"))?;
        let bytes = open_segment(sek, KIND, id, &sealed)?;
        let prior = Skdm::from_wire(&bytes)?;
        prior.verify(author_root, room, release.body.epoch)?;
        if key != self::key(&prior.body.author_id, prior.body.epoch, prior.body.chain_id) {
            return Err(Error::MalformedAtRest("receiver release source binding"));
        }
        if prior.body.signing_pubkey != release.body.signing_pubkey {
            return Err(Error::MalformedAtRest(
                "receiver release signing key changed",
            ));
        }
        if prior.body.iteration == release.body.iteration {
            if prior.body.canonical_body().as_slice() != release.body.canonical_body().as_slice() {
                return Err(Error::MalformedAtRest("receiver release floor conflicts"));
            }
            return Ok(Remember::Unchanged);
        }
        if prior.body.iteration < release.body.iteration {
            return Ok(Remember::Unchanged);
        }
    } else if header.count >= MAX_RECEIVER_CHAINS {
        // Retired objects still consume their existing receiver-slot capacity until physical
        // deletion. Nothing is acknowledged or installed while that capacity is unavailable.
        if !header.cleanup {
            return Err(Error::MalformedAtRest(
                "receiver release capacity has no retirement",
            ));
        }
        if !header.retry_owed {
            header.retry_owed = true;
            header.seal(batch, sek, room)?;
        }
        return Ok(Remember::Busy);
    }
    let wire = release.to_wire();
    if wire.len() > RELEASE_BYTES {
        return Err(Error::SizeLimitExceeded("signed receiver release"));
    }
    let id = header.next;
    header.next = id.checked_add(1).ok_or(Error::MalformedAtRest(
        "receiver release allocator exhausted",
    ))?;
    let sealed = seal_segment(sek, KIND, id, &wire)?;
    batch.put_segment(room, KIND, id, &sealed)?;
    {
        let mut tree = session_tree::Write::new(batch, sek, room, KIND, header.next)?;
        header.root = tree.set(header.root, key, Some(id))?;
        header.next = tree.next_page();
    }
    if let Some(old) = old {
        batch.delete_segment(room, KIND, old)?;
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

/// At most one existing bounded tree lookup and one COW deletion per room maintenance turn.
/// No release body/key is opened to discard a slot; each committed cursor is restartable.
pub(super) fn advance(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    receivers: &BTreeMap<(Digest32, u64), ReceiverChain>,
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
            if header.retry_owed {
                return Err(Error::MalformedAtRest(
                    "receiver release retry has no stale slot",
                ));
            }
            header.cleanup = false;
            header.after = None;
        }
        Some((key, id)) => {
            let (author, epoch, chain) = slot(&key)?;
            if !receivers
                .get(&(author, chain))
                .is_some_and(|receiver| receiver.epoch() == epoch)
            {
                {
                    let mut tree = session_tree::Write::new(batch, sek, room, KIND, header.next)?;
                    header.root = tree.set(header.root, key, None)?;
                    header.next = tree.next_page();
                }
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
