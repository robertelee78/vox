//! Authenticated exact-hash legacy Session subtype evidence (#804).
//!
//! Two sealed pages per log-id namespace: the even page records a target's known subtype;
//! the odd page holds the remaining references of that entry's authenticated declaration.
//! Pending pages follow local first-seen and ordinary retention. A resolved target page lives
//! with its verified skeleton, independently of the declaration's later expiry. No page grants
//! drive or changes `owed_wants`: subtype and permission eligibility are separate facts.

use super::*;
use crate::node::content::{LegacySessionIndex, MAX_LEGACY_SESSION_HASHES};

#[path = "legacy_projection.rs"]
mod projection;
pub(super) use projection::LegacyProjectionContext;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Page {
    Pending {
        declaration: Digest32,
        author: Digest32,
        first_seen: u64,
        steps: Vec<Digest32>,
    },
    Target {
        hash: Digest32,
        author: Digest32,
        session: bool,
    },
}

impl Page {
    fn wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Self::Pending {
                declaration,
                author,
                first_seen,
                steps,
            } => {
                e.array(6)
                    .uint(1)
                    .uint(0)
                    .bytes(declaration)
                    .bytes(author)
                    .uint(*first_seen)
                    .array(steps.len());
                for hash in steps {
                    e.bytes(hash);
                }
            }
            Self::Target {
                hash,
                author,
                session,
            } => {
                e.array(4)
                    .uint(1)
                    .uint(if *session { 1 } else { 2 })
                    .bytes(hash)
                    .bytes(author);
            }
        }
        e.finish()
    }

    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let arity = d.array()?;
        if d.uint()? != 1 {
            return Err(Error::MalformedAtRest("Session classification version"));
        }
        let kind = d.uint()?;
        let hash = digest(&mut d)?;
        let author = digest(&mut d)?;
        let page = match (arity, kind) {
            (4, 1 | 2) => Self::Target {
                hash,
                author,
                session: kind == 1,
            },
            (6, 0) => {
                let first_seen = d.uint()?;
                let n = d.array()?;
                if n == 0 || n > MAX_LEGACY_SESSION_HASHES {
                    return Err(Error::MalformedAtRest("Session classification length"));
                }
                let mut steps = Vec::with_capacity(n);
                for _ in 0..n {
                    let h = digest(&mut d)?;
                    if steps.last().is_some_and(|last| *last >= h) {
                        return Err(Error::MalformedAtRest("Session classification order"));
                    }
                    steps.push(h);
                }
                Self::Pending {
                    declaration: hash,
                    author,
                    first_seen,
                    steps,
                }
            }
            _ => return Err(Error::MalformedAtRest("Session classification page")),
        };
        d.finish()?;
        Ok(page)
    }
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("Session classification digest"))
}

fn page_id(log_id: u64, pending: bool) -> Result<u64> {
    log_id
        .checked_mul(2)
        .and_then(|id| id.checked_add(u64::from(pending)))
        .ok_or(Error::SizeLimitExceeded("Session classification pages"))
}

// LogDb starts at one, leaving page zero for bounded reconciliation state.
const HEADER: u64 = 0;
const WORK_SLOTS: usize = 64;
const PAGE_BYTES: usize = MAX_LEGACY_SESSION_HASHES * 34 + 256;
const REFRESHING: &str = "legacy Session classification is refreshing";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Header {
    revision: u64,
    initialized: bool,
    pending: bool,
    active: bool,
    after: u64,
    through: u64,
    current: u64,
    offset: usize,
    unresolved: bool,
    again: bool,
}

impl Header {
    fn empty(initialized: bool) -> Self {
        Self {
            revision: 0,
            initialized,
            pending: !initialized,
            active: false,
            after: 1,
            through: 1,
            current: 0,
            offset: 0,
            unresolved: false,
            again: false,
        }
    }

    fn wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(11)
            .uint(1)
            .uint(self.revision)
            .uint(u64::from(self.initialized))
            .uint(u64::from(self.pending))
            .uint(u64::from(self.active))
            .uint(self.after)
            .uint(self.through)
            .uint(self.current)
            .uint(self.offset as u64)
            .uint(u64::from(self.unresolved))
            .uint(u64::from(self.again));
        e.finish()
    }

    fn read(bytes: &[u8]) -> Result<Self> {
        fn flag(d: &mut Decoder<'_>) -> Result<bool> {
            match d.uint()? {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(Error::MalformedAtRest("Session classification cursor flag")),
            }
        }
        let mut d = Decoder::new(bytes);
        if d.array()? != 11 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest(
                "Session classification cursor version",
            ));
        }
        let header = Self {
            revision: d.uint()?,
            initialized: flag(&mut d)?,
            pending: flag(&mut d)?,
            active: flag(&mut d)?,
            after: d.uint()?,
            through: d.uint()?,
            current: d.uint()?,
            offset: usize::try_from(d.uint()?)
                .map_err(|_| Error::MalformedAtRest("Session classification cursor offset"))?,
            unresolved: flag(&mut d)?,
            again: flag(&mut d)?,
        };
        if header.after < 1
            || header.after > header.through
            || (header.current != 0
                && (header.current <= header.after || header.current > header.through))
            || header.offset > MAX_LEGACY_SESSION_HASHES
            || (header.offset != 0 && header.current == 0)
            || (!header.active && (header.current != 0 || header.offset != 0 || header.again))
        {
            return Err(Error::MalformedAtRest("Session classification cursor"));
        }
        d.finish()?;
        Ok(header)
    }

    fn changed(&mut self) -> Result<()> {
        self.revision = self.revision.checked_add(1).ok_or(Error::MalformedAtRest(
            "Session classification revision exhausted",
        ))?;
        Ok(())
    }
}

/// Only scalar publication state is resident. Pages and pending references remain sealed.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct LegacySessions {
    display_revision: u64,
    /// The caller's current Batch contains classification writes and must be committed.
    dirty: bool,
}

impl LegacySessions {
    pub(super) fn display_revision(&self) -> u64 {
        self.display_revision
    }

    pub(super) fn dirty(&self) -> bool {
        self.dirty
    }

    pub(super) fn committed(&mut self) {
        self.dirty = false;
    }
}

fn segment(
    transaction: Transaction<'_, '_>,
    room: &Digest32,
    id: u64,
) -> Result<Option<crate::atrest::store::SealedSegment>> {
    match transaction {
        Transaction::Snapshot(snapshot) => {
            snapshot.get_segment(room, SegmentKind::SessionClassification, id)
        }
        Transaction::Batch(batch) => {
            batch.get_segment(room, SegmentKind::SessionClassification, id)
        }
    }
}

fn next_id(transaction: Transaction<'_, '_>, room: &Digest32, after: u64) -> Result<Option<u64>> {
    match transaction {
        Transaction::Snapshot(snapshot) => {
            snapshot.segment_id_after(room, SegmentKind::SessionClassification, Some(after))
        }
        Transaction::Batch(batch) => {
            batch.segment_id_after(room, SegmentKind::SessionClassification, Some(after))
        }
    }
}

impl ChannelState {
    /// Exact retry classification; malformed or unreadable sealed facts remain errors.
    pub fn legacy_classification_refreshing(error: &Error) -> bool {
        matches!(error, Error::Profile(why) if *why == REFRESHING)
    }

    /// Read-only consumers use only persisted subtype evidence for a missing-body row.
    /// There is no receiver-chain borrow/copy and no classification maintenance here.
    pub(super) fn saved_owed_classification(
        rendered: &entry_store::RenderView<'_>,
        room: &Digest32,
        entry: &Entry,
        verified_head: u64,
    ) -> Result<bool> {
        if entry.skeleton.v2.is_some() {
            return Ok(false);
        }
        let transaction = Transaction::Snapshot(rendered.snapshot());
        let hash = entry.entry_hash();
        if entry.skeleton.channel_id != *room {
            return Err(Error::MalformedAtRest(
                "Session classification source unverified",
            ));
        }
        if entry.skeleton.seq <= verified_head {
            if let Some(log) = rendered.read_index().log_id(&hash)? {
                let id = page_id(log, false)?;
                if let Some(sealed) = segment(transaction, room, id)? {
                    if sealed.ciphertext.len() > PAGE_BYTES + crate::atrest::sek::TAG_LEN {
                        return Err(Error::MalformedAtRest("Session classification page size"));
                    }
                    return match Page::read(&open_segment(
                        rendered.key(),
                        SegmentKind::SessionClassification,
                        id,
                        &sealed,
                    )?)? {
                        Page::Target {
                            hash: saved,
                            author,
                            session,
                        } if saved == hash && author == entry.skeleton.author_id => Ok(session),
                        _ => Err(Error::MalformedAtRest(
                            "Session classification target binding",
                        )),
                    };
                }
            }
        }
        Self::saved_classification_complete(rendered, room)?;
        Ok(false)
    }

    pub(super) fn saved_classification_complete(
        rendered: &entry_store::RenderView<'_>,
        room: &Digest32,
    ) -> Result<()> {
        let transaction = Transaction::Snapshot(rendered.snapshot());
        let header = match segment(transaction, room, HEADER)? {
            Some(sealed) => {
                if sealed.ciphertext.len() > 256 {
                    return Err(Error::MalformedAtRest("Session classification cursor size"));
                }
                Header::read(&open_segment(
                    rendered.key(),
                    SegmentKind::SessionClassification,
                    HEADER,
                    &sealed,
                )?)?
            }
            None => Header::empty(next_id(transaction, room, 1)?.is_none()),
        };
        if header.active || !header.initialized {
            return Err(Error::Profile(REFRESHING));
        }
        Ok(())
    }

    /// Load only the sealed cursor. Existing subtype pages are checked on lookup or one
    /// bounded reconciliation turn; reopening never materializes the retained classification set.
    pub(super) fn restore_legacy_sessions(&mut self, store: &Store, _now_ms: u64) -> Result<()> {
        let mut batch = store.batch()?;
        batch.derived();
        let mut header = self.legacy_header(Transaction::Batch(&batch))?;
        self.request_legacy_pass(&batch, &mut header)?;
        self.legacy_sessions.display_revision = header.revision;
        if self.legacy_header(Transaction::Batch(&batch))? != header {
            self.save_legacy_header(&mut batch, &header)?;
            batch.commit()?;
            self.legacy_sessions.committed();
        }
        Ok(())
    }
}
