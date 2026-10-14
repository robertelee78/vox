//! Session projection pages in the room's existing Store. Tree pages and compact descriptor
//! rows share one allocator and one Batch; only the committed header publishes their roots.

use crate::atrest::sek::{Sek, TAG_LEN};
use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::store::{Batch, Snapshot};
use zeroize::Zeroizing;

use super::super::entry_store::session_tree;
use super::activity_state::{ActivityState, ActivityTree};
use super::record::Key;

const KIND: SegmentKind = SegmentKind::SessionIndex;
const HEADER: u64 = 0;
// Descriptors contain source references, never the referenced text. This bounds decoded
// descriptor allocation and is not a bound on any member-written metadata field.
const DESCRIPTOR_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy)]
pub(super) enum Tree {
    PrivateHash,
    PrivateArrival,
    Candidates,
    Groups,
    Openings,
    Parts,
    LogicalRecords,
    Files,
    Activities,
    Requests,
    Outcomes,
    Pending,
    Gathered,
    Bundles,
    Envelopes,
    Events,
    OpeningHash,
    Counts,
    AuthorOpenings,
    OpenCounts,
    ActivityFacts,
    ActivityRaw,
    ActivityCounts,
    ActivitySessions,
    ActivityCreated,
    Lifecycle,
    RefreshRecords,
    PrivateAge,
    PrivateStepAge,
    Controls,
}

const TREES: usize = 30;

impl Tree {
    fn index(self) -> usize {
        match self {
            Self::PrivateHash => 0,
            Self::PrivateArrival => 1,
            Self::Candidates => 2,
            Self::Groups => 3,
            Self::Openings => 4,
            Self::Parts => 5,
            Self::LogicalRecords => 6,
            Self::Files => 7,
            Self::Activities => 8,
            Self::Requests => 9,
            Self::Outcomes => 10,
            Self::Pending => 11,
            Self::Gathered => 12,
            Self::Bundles => 13,
            Self::Envelopes => 14,
            Self::Events => 15,
            Self::OpeningHash => 16,
            Self::Counts => 17,
            Self::AuthorOpenings => 18,
            Self::OpenCounts => 19,
            Self::ActivityFacts => 20,
            Self::ActivityRaw => 21,
            Self::ActivityCounts => 22,
            Self::ActivitySessions => 23,
            Self::ActivityCreated => 24,
            Self::Lifecycle => 25,
            Self::RefreshRecords => 26,
            Self::PrivateAge => 27,
            Self::PrivateStepAge => 28,
            Self::Controls => 29,
        }
    }
}

fn invalid(why: &'static str) -> Error {
    Error::MalformedAtRest(why)
}

#[derive(Clone)]
pub(super) struct Header {
    roots: [u64; TREES],
    next: u64,
    pub revision: u64,
    pub private_after: Option<u64>,
    pub public_after: Option<(u64, u64, Digest32)>,
    pub ready: bool,
    pub private_generation: u64,
    pub activity_generation: u64,
    pub published: Option<(u64, u64)>,
    pub building: Option<Building>,
    pub activity: ActivityState,
}

/// Fixed-size progress, never a list of sources, fields, or pages. Work roots stay
/// unpublished until the whole fold has succeeded. Cleanup is itself a bounded walk.
#[derive(Clone)]
pub(super) struct Building {
    pub public: u64,
    pub private: u64,
    pub phase: u8,
    pub cursor: Option<Key>,
    roots: [u64; TREES],
    pub cleanup: usize,
}

impl Building {
    pub fn new(public: u64, private: u64) -> Self {
        Self {
            public,
            private,
            phase: 1,
            cursor: None,
            roots: [0; TREES],
            cleanup: 0,
        }
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            roots: [0; TREES],
            next: 1,
            revision: 0,
            private_after: None,
            public_after: None,
            ready: false,
            private_generation: 0,
            activity_generation: 0,
            published: None,
            building: None,
            activity: ActivityState::default(),
        }
    }
}

impl Header {
    fn bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut e = Encoder::new();
        e.array(12)
            .uint(1)
            .uint(self.next)
            .uint(self.revision)
            .array(TREES);
        for root in self.roots {
            e.uint(root);
        }
        e.array(usize::from(self.private_after.is_some()));
        if let Some(after) = self.private_after {
            e.uint(after);
        }
        e.array(usize::from(self.public_after.is_some()));
        if let Some((created, clock, hash)) = self.public_after {
            e.array(3).uint(created).uint(clock).bytes(&hash);
        }
        e.uint(u64::from(self.ready));
        e.uint(self.private_generation);
        e.uint(self.activity_generation);
        e.array(usize::from(self.published.is_some()));
        if let Some((public, private)) = self.published {
            e.array(2).uint(public).uint(private);
        }
        e.array(usize::from(self.building.is_some()));
        if let Some(work) = &self.building {
            e.array(6)
                .uint(work.public)
                .uint(work.private)
                .uint(u64::from(work.phase))
                .bytes(work.cursor.as_ref().map_or(&[][..], |key| &key[..]))
                .array(TREES);
            for root in work.roots {
                e.uint(root);
            }
            e.uint(work.cleanup as u64);
        }
        self.activity.put(&mut e);
        Zeroizing::new(e.finish())
    }

    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 12 || d.uint()? != 1 {
            return Err(invalid("Session index header version"));
        }
        let next = d.uint()?;
        let revision = d.uint()?;
        let stored_trees = d.array()?;
        // These are append-only derived roots within the current development format. Keep
        // every original locator; startup streams the absent private/control facts.
        if next == 0 || !matches!(stored_trees, 26 | 29 | TREES) {
            return Err(invalid("Session index header roots"));
        }
        let mut roots = [0; TREES];
        for root in &mut roots[..stored_trees] {
            *root = d.uint()?;
            if *root >= next {
                return Err(invalid("Session index root exceeds allocator"));
            }
        }
        let private_after = match d.array()? {
            0 => None,
            1 => Some(d.uint()?),
            _ => return Err(invalid("Session index private cursor")),
        };
        let public_after = match d.array()? {
            0 => None,
            1 => {
                if d.array()? != 3 {
                    return Err(invalid("Session index public cursor arity"));
                }
                Some((
                    d.uint()?,
                    d.uint()?,
                    d.bytes()?
                        .try_into()
                        .map_err(|_| invalid("Session index public cursor hash"))?,
                ))
            }
            _ => return Err(invalid("Session index public cursor")),
        };
        let ready = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(invalid("Session index ready state")),
        };
        let private_generation = d.uint()?;
        let activity_generation = d.uint()?;
        let published = match d.array()? {
            0 => None,
            1 => {
                if d.array()? != 2 {
                    return Err(invalid("Session published revision"));
                }
                Some((d.uint()?, d.uint()?))
            }
            _ => return Err(invalid("Session published revision option")),
        };
        let building = match d.array()? {
            0 => None,
            1 => {
                if d.array()? != 6 {
                    return Err(invalid("Session build state"));
                }
                let public = d.uint()?;
                let private = d.uint()?;
                let phase = u8::try_from(d.uint()?).map_err(|_| invalid("Session build phase"))?;
                if !(1..=7).contains(&phase) {
                    return Err(invalid("Session build phase"));
                }
                let cursor = match d.bytes()? {
                    [] => None,
                    bytes => Some(
                        bytes
                            .try_into()
                            .map_err(|_| invalid("Session build cursor"))?,
                    ),
                };
                if d.array()? != stored_trees {
                    return Err(invalid("Session build roots"));
                }
                let mut roots = [0; TREES];
                for root in &mut roots[..stored_trees] {
                    *root = d.uint()?;
                    if *root >= next {
                        return Err(invalid("Session work root exceeds allocator"));
                    }
                }
                let cleanup =
                    usize::try_from(d.uint()?).map_err(|_| invalid("Session cleanup index"))?;
                if cleanup > TREES {
                    return Err(invalid("Session cleanup index"));
                }
                Some(Building {
                    public,
                    private,
                    phase,
                    cursor,
                    roots,
                    cleanup,
                })
            }
            _ => return Err(invalid("Session build state option")),
        };
        let activity = ActivityState::read(&mut d, next)?;
        d.finish()?;
        Ok(Self {
            roots,
            next,
            revision,
            private_after,
            public_after,
            ready,
            private_generation,
            activity_generation,
            published,
            building,
            activity,
        })
    }
}

pub(super) struct Read<'a> {
    snapshot: &'a Snapshot,
    sek: &'a Sek,
    room: &'a Digest32,
    pub header: Header,
    working: bool,
}

impl<'a> Read<'a> {
    pub fn waiting_find(&self, root: u64, key: &Key) -> Result<Option<u64>> {
        session_tree::Read::snapshot(self.snapshot, self.sek, self.room, KIND).find(root, key)
    }
    fn activity_root(&self, tree: ActivityTree) -> u64 {
        self.header.activity.roots[tree.index()]
    }
    pub fn activity_find(&self, tree: ActivityTree, key: &Key) -> Result<Option<u64>> {
        session_tree::Read::snapshot(self.snapshot, self.sek, self.room, KIND)
            .find(self.activity_root(tree), key)
    }
    pub fn activity_next(
        &self,
        tree: ActivityTree,
        after: Option<Key>,
    ) -> Result<Option<(Key, u64)>> {
        session_tree::Read::snapshot(self.snapshot, self.sek, self.room, KIND)
            .first_after(self.activity_root(tree), after)
    }
    pub fn activity_previous(
        &self,
        tree: ActivityTree,
        before: Option<Key>,
    ) -> Result<Option<(Key, u64)>> {
        session_tree::Read::snapshot(self.snapshot, self.sek, self.room, KIND)
            .last_before(self.activity_root(tree), before)
    }
    pub fn open(snapshot: &'a Snapshot, sek: &'a Sek, room: &'a Digest32) -> Result<Self> {
        Self::existing(snapshot, sek, room)?
            .ok_or_else(|| invalid("Session projection is not prepared"))
    }

    pub fn existing(
        snapshot: &'a Snapshot,
        sek: &'a Sek,
        room: &'a Digest32,
    ) -> Result<Option<Self>> {
        let Some(sealed) = snapshot.get_segment(room, KIND, HEADER)? else {
            return Ok(None);
        };
        if sealed.ciphertext.len() > DESCRIPTOR_BYTES + TAG_LEN {
            return Err(invalid("Session header exceeds its format"));
        }
        let bytes = open_segment(sek, KIND, HEADER, &sealed)?;
        let header = Header::read(&bytes)?;
        Ok(Some(Self {
            snapshot,
            sek,
            room,
            header,
            working: false,
        }))
    }

    pub fn find(&self, tree: Tree, key: &Key) -> Result<Option<u64>> {
        session_tree::Read::snapshot(self.snapshot, self.sek, self.room, KIND)
            .find(self.root(tree)?, key)
    }

    pub fn source(&self, source: super::record::Source) -> Result<String> {
        super::source::body(self.snapshot, self.sek, self.room, source)
    }

    pub fn next(&self, tree: Tree, after: Option<Key>) -> Result<Option<(Key, u64)>> {
        session_tree::Read::snapshot(self.snapshot, self.sek, self.room, KIND)
            .first_after(self.root(tree)?, after)
    }

    pub fn previous(&self, tree: Tree, before: Option<Key>) -> Result<Option<(Key, u64)>> {
        session_tree::Read::snapshot(self.snapshot, self.sek, self.room, KIND)
            .last_before(self.root(tree)?, before)
    }

    pub fn work(mut self) -> Result<Self> {
        if self.header.building.is_none() {
            return Err(invalid("Session work roots absent"));
        }
        self.working = true;
        Ok(self)
    }

    pub(super) fn root(&self, tree: Tree) -> Result<u64> {
        if self.working {
            Ok(self
                .header
                .building
                .as_ref()
                .ok_or_else(|| invalid("Session work roots absent"))?
                .roots[tree.index()])
        } else {
            Ok(self.header.roots[tree.index()])
        }
    }

    pub fn descriptor(&self, id: u64) -> Result<Zeroizing<Vec<u8>>> {
        if id == HEADER || id >= self.header.next {
            return Err(invalid("Session descriptor id"));
        }
        let sealed = self
            .snapshot
            .get_segment(self.room, KIND, id)?
            .ok_or_else(|| invalid("Session descriptor missing"))?;
        // Check sealed length before decrypting and allocating its plaintext.
        if sealed.ciphertext.len() > DESCRIPTOR_BYTES + TAG_LEN {
            return Err(invalid("Session descriptor exceeds its format"));
        }
        let bytes = open_segment(self.sek, KIND, id, &sealed)?;
        if bytes.len() > DESCRIPTOR_BYTES {
            return Err(invalid("Session descriptor exceeds its format"));
        }
        Ok(bytes)
    }
}

pub(super) struct Write<'a, 's> {
    batch: &'a mut Batch<'s>,
    sek: &'a Sek,
    room: &'a Digest32,
    pub header: Header,
    working: bool,
    activity_working: bool,
}

pub(super) fn find_in(
    batch: &Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    tree: Tree,
    key: &Key,
) -> Result<Option<u64>> {
    let Some(sealed) = batch.get_segment(room, KIND, HEADER)? else {
        return Ok(None);
    };
    if sealed.ciphertext.len() > DESCRIPTOR_BYTES + TAG_LEN {
        return Err(invalid("Session header exceeds its format"));
    }
    let header = Header::read(&open_segment(sek, KIND, HEADER, &sealed)?)?;
    session_tree::Read::batch(batch, sek, room, KIND).find(header.roots[tree.index()], key)
}

impl<'a, 's> Write<'a, 's> {
    pub fn activity_is_working(&self) -> bool {
        self.activity_working
    }
    pub fn waiting_find(&self, root: u64, key: &Key) -> Result<Option<u64>> {
        session_tree::Read::batch(self.batch, self.sek, self.room, KIND).find(root, key)
    }
    pub fn waiting_next(&self, root: u64, after: Option<Key>) -> Result<Option<(Key, u64)>> {
        session_tree::Read::batch(self.batch, self.sek, self.room, KIND).first_after(root, after)
    }
    pub fn waiting_set(&mut self, root: u64, key: Key, value: Option<u64>) -> Result<u64> {
        let mut pages =
            session_tree::Write::new(self.batch, self.sek, self.room, KIND, self.header.next)?;
        let root = pages.set(root, key, value)?;
        self.header.next = pages.next_page();
        Ok(root)
    }
    pub fn activity_work(mut self) -> Result<Self> {
        if self.header.activity.work.is_none() {
            return Err(invalid("Session activity work absent"));
        }
        self.activity_working = true;
        Ok(self)
    }
    fn activity_root(&self, tree: ActivityTree) -> Result<u64> {
        if self.activity_working {
            Ok(self
                .header
                .activity
                .work
                .as_ref()
                .ok_or_else(|| invalid("Session activity work absent"))?
                .roots[tree.index()])
        } else {
            Ok(self.header.activity.roots[tree.index()])
        }
    }
    pub fn activity_find(&self, tree: ActivityTree, key: &Key) -> Result<Option<u64>> {
        session_tree::Read::batch(self.batch, self.sek, self.room, KIND)
            .find(self.activity_root(tree)?, key)
    }
    pub fn activity_next(
        &self,
        tree: ActivityTree,
        after: Option<Key>,
    ) -> Result<Option<(Key, u64)>> {
        session_tree::Read::batch(self.batch, self.sek, self.room, KIND)
            .first_after(self.activity_root(tree)?, after)
    }
    pub fn activity_set(&mut self, tree: ActivityTree, key: Key, value: Option<u64>) -> Result<()> {
        let old = self.activity_root(tree)?;
        let mut pages =
            session_tree::Write::new(self.batch, self.sek, self.room, KIND, self.header.next)?;
        let root = pages.set(old, key, value)?;
        self.header.next = pages.next_page();
        if self.activity_working {
            self.header
                .activity
                .work
                .as_mut()
                .ok_or_else(|| invalid("Session activity work absent"))?
                .roots[tree.index()] = root;
        } else {
            self.header.activity.roots[tree.index()] = root;
        }
        Ok(())
    }
    pub fn publish_activity(&mut self) -> Result<()> {
        let work = self
            .header
            .activity
            .work
            .as_mut()
            .ok_or_else(|| invalid("Session activity work absent"))?;
        std::mem::swap(&mut self.header.activity.roots, &mut work.roots);
        self.header.activity.applied = work.boundary;
        self.header.activity.ready = true;
        work.phase = 5;
        work.cursor = None;
        work.cleanup = 0;
        Ok(())
    }
    pub fn cleanup_activity(&mut self, limit: usize) -> Result<()> {
        self.activity_working = true;
        for _ in 0..limit {
            let at = self
                .header
                .activity
                .work
                .as_ref()
                .ok_or_else(|| invalid("Session activity work absent"))?
                .cleanup;
            let Some(tree) = super::activity_state::ALL.get(at).copied() else {
                self.header.activity.work = None;
                self.activity_working = false;
                break;
            };
            if let Some((key, _)) = self.activity_next(tree, None)? {
                self.activity_set(tree, key, None)?;
            } else {
                self.header
                    .activity
                    .work
                    .as_mut()
                    .ok_or_else(|| invalid("Session activity work absent"))?
                    .cleanup += 1;
            }
        }
        Ok(())
    }
    pub fn open(batch: &'a mut Batch<'s>, sek: &'a Sek, room: &'a Digest32) -> Result<Self> {
        let header = match batch.get_segment(room, KIND, HEADER)? {
            Some(sealed) => {
                if sealed.ciphertext.len() > DESCRIPTOR_BYTES + TAG_LEN {
                    return Err(invalid("Session header exceeds its format"));
                }
                Header::read(&open_segment(sek, KIND, HEADER, &sealed)?)?
            }
            None => Header::default(),
        };
        Ok(Self {
            batch,
            sek,
            room,
            header,
            working: false,
            activity_working: false,
        })
    }

    pub fn find(&self, tree: Tree, key: &Key) -> Result<Option<u64>> {
        session_tree::Read::batch(self.batch, self.sek, self.room, KIND).find(self.root(tree)?, key)
    }

    pub fn next(&self, tree: Tree, after: Option<Key>) -> Result<Option<(Key, u64)>> {
        session_tree::Read::batch(self.batch, self.sek, self.room, KIND)
            .first_after(self.root(tree)?, after)
    }

    pub fn work(mut self) -> Result<Self> {
        if self.header.building.is_none() {
            return Err(invalid("Session work roots absent"));
        }
        self.working = true;
        Ok(self)
    }

    pub(super) fn root(&self, tree: Tree) -> Result<u64> {
        if self.working {
            Ok(self
                .header
                .building
                .as_ref()
                .ok_or_else(|| invalid("Session work roots absent"))?
                .roots[tree.index()])
        } else {
            Ok(self.header.roots[tree.index()])
        }
    }

    pub fn descriptor(&self, id: u64) -> Result<Zeroizing<Vec<u8>>> {
        if id == HEADER || id >= self.header.next {
            return Err(invalid("Session descriptor id"));
        }
        let sealed = self
            .batch
            .get_segment(self.room, KIND, id)?
            .ok_or_else(|| invalid("Session descriptor missing"))?;
        if sealed.ciphertext.len() > DESCRIPTOR_BYTES + TAG_LEN {
            return Err(invalid("Session descriptor exceeds its format"));
        }
        open_segment(self.sek, KIND, id, &sealed)
    }

    pub fn set(&mut self, tree: Tree, key: Key, value: Option<u64>) -> Result<()> {
        let old = self.root(tree)?;
        let mut pages =
            session_tree::Write::new(self.batch, self.sek, self.room, KIND, self.header.next)?;
        let root = pages.set(old, key, value)?;
        self.header.next = pages.next_page();
        if self.working {
            self.header
                .building
                .as_mut()
                .ok_or_else(|| invalid("Session work roots absent"))?
                .roots[tree.index()] = root;
        } else {
            self.header.roots[tree.index()] = root;
        }
        Ok(())
    }

    pub fn put_descriptor(&mut self, bytes: &[u8]) -> Result<u64> {
        if bytes.len() > DESCRIPTOR_BYTES {
            return Err(invalid("Session descriptor exceeds its format"));
        }
        let id = self.header.next;
        self.header.next = id
            .checked_add(1)
            .ok_or_else(|| invalid("Session index allocator exhausted"))?;
        let sealed = seal_segment(self.sek, KIND, id, bytes)?;
        self.batch.put_segment(self.room, KIND, id, &sealed)?;
        Ok(id)
    }

    pub fn delete_descriptor(&mut self, id: u64) -> Result<()> {
        if id == HEADER || id >= self.header.next {
            return Err(invalid("Session descriptor id"));
        }
        self.batch.delete_segment(self.room, KIND, id).map(|_| ())
    }

    pub fn replace_descriptor(&mut self, id: u64, bytes: &[u8]) -> Result<()> {
        if id == 0 || id >= self.header.next || bytes.len() > DESCRIPTOR_BYTES {
            return Err(invalid("Session descriptor replacement"));
        }
        let sealed = seal_segment(self.sek, KIND, id, bytes)?;
        self.batch.put_segment(self.room, KIND, id, &sealed)
    }

    pub fn publish(&mut self) -> Result<()> {
        let work = self
            .header
            .building
            .as_mut()
            .ok_or_else(|| invalid("Session work roots absent"))?;
        for tree in [
            Tree::Groups,
            Tree::Openings,
            Tree::Parts,
            Tree::OpeningHash,
            Tree::Counts,
            Tree::AuthorOpenings,
            Tree::OpenCounts,
            Tree::Lifecycle,
        ] {
            std::mem::swap(
                &mut self.header.roots[tree.index()],
                &mut work.roots[tree.index()],
            );
        }
        self.header.published = Some((work.public, work.private));
        self.header.ready = true;
        work.phase = 7;
        work.cursor = None;
        work.cleanup = 0;
        Ok(())
    }

    /// Retire at most `limit` old records/paths. Shared descriptor references (Groups and
    /// logical dedup) do not own their values; their owning tree deletes each record once.
    pub fn cleanup(&mut self, limit: usize) -> Result<bool> {
        const ALL: [Tree; TREES] = [
            Tree::PrivateHash,
            Tree::PrivateArrival,
            Tree::Candidates,
            Tree::Groups,
            Tree::Openings,
            Tree::Parts,
            Tree::LogicalRecords,
            Tree::Files,
            Tree::Activities,
            Tree::Requests,
            Tree::Outcomes,
            Tree::Pending,
            Tree::Gathered,
            Tree::Bundles,
            Tree::Envelopes,
            Tree::Events,
            Tree::OpeningHash,
            Tree::Counts,
            Tree::AuthorOpenings,
            Tree::OpenCounts,
            Tree::ActivityFacts,
            Tree::ActivityRaw,
            Tree::ActivityCounts,
            Tree::ActivitySessions,
            Tree::ActivityCreated,
            Tree::Lifecycle,
            Tree::RefreshRecords,
            Tree::PrivateAge,
            Tree::PrivateStepAge,
            Tree::Controls,
        ];
        self.working = true;
        for _ in 0..limit {
            let at = self
                .header
                .building
                .as_ref()
                .ok_or_else(|| invalid("Session work roots absent"))?
                .cleanup;
            let Some(tree) = ALL.get(at).copied() else {
                self.header.building = None;
                self.working = false;
                return Ok(true);
            };
            if let Some((key, id)) = self.next(tree, None)? {
                self.set(tree, key, None)?;
                if !matches!(
                    tree,
                    Tree::Groups
                        | Tree::LogicalRecords
                        | Tree::PrivateHash
                        | Tree::PrivateArrival
                        | Tree::Files
                        | Tree::OpeningHash
                        | Tree::Counts
                        | Tree::AuthorOpenings
                        | Tree::OpenCounts
                        | Tree::ActivityRaw
                        | Tree::ActivityCounts
                        | Tree::ActivitySessions
                        | Tree::ActivityCreated
                        | Tree::Lifecycle
                ) {
                    self.delete_descriptor(id)?;
                }
            } else {
                self.header
                    .building
                    .as_mut()
                    .ok_or_else(|| invalid("Session work roots absent"))?
                    .cleanup += 1;
            }
        }
        Ok(false)
    }

    pub fn seal(mut self) -> Result<()> {
        self.header.revision = self
            .header
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("Session projection revision exhausted"))?;
        let sealed = seal_segment(self.sek, KIND, HEADER, &self.header.bytes())?;
        self.batch.put_segment(self.room, KIND, HEADER, &sealed)
    }
}
