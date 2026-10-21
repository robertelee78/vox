//! Signed Session authorization facts share the existing sealed Session index. Exact floors
//! remain durable; only a fixed cursor is needed to prove continuity across old generations.

use super::record::Key;
use super::storage::{self, Read, Tree, Write};
use crate::atrest::sek::Sek;
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::channel::entry_store::Transaction;
use crate::node::channel::session_floor::Floor;
use crate::node::drive::{SessionFloorBoundary, SessionFloorKey};
use crate::node::store::Store;

type Generation = (u64, u64);
pub(in crate::node::channel) const REFRESHING: &str = "Session authorization facts are refreshing";
pub(in crate::node::channel) fn refreshing(error: &Error) -> bool {
    matches!(error, Error::StreamRefused(REFRESHING))
}
fn bad() -> Error {
    Error::MalformedAtRest("Session authorization index")
}
fn author_key(author: &Digest32) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(author);
    key
}
fn generation_key(author: &Digest32, generation: Generation) -> Key {
    let mut key = author_key(author);
    key[32..40].copy_from_slice(&generation.0.to_be_bytes());
    key[40..48].copy_from_slice(&generation.1.to_be_bytes());
    key
}
fn generation(key: &Key) -> Generation {
    let mut epoch = [0; 8];
    let mut generation = [0; 8];
    epoch.copy_from_slice(&key[32..40]);
    generation.copy_from_slice(&key[40..48]);
    (u64::from_be_bytes(epoch), u64::from_be_bytes(generation))
}
fn pair(author: &Digest32, recipient: &Digest32) -> Digest32 {
    crate::hash::sha256_concat(&[b"vox/session-floor-pair/v1", author, recipient])
}
fn floor_key(key: &SessionFloorKey) -> Key {
    generation_key(&pair(&key.0, &key.1), (key.2, key.3))
}
fn boundary(bytes: &[u8]) -> Result<SessionFloorBoundary> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 4 || d.uint()? != 1 {
        return Err(bad());
    }
    let value = (d.uint()?, d.uint()?, d.uint()?);
    d.finish()?;
    Ok(value)
}
fn boundary_bytes(value: SessionFloorBoundary) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(4).uint(1).uint(value.0).uint(value.1).uint(value.2);
    e.finish()
}
fn descriptor(
    transaction: Transaction<'_, '_>,
    sek: &Sek,
    room: &Digest32,
    tree: Tree,
    key: &Key,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    match transaction {
        Transaction::Snapshot(snapshot) => {
            let Some(read) = Read::existing(snapshot, sek, room)? else {
                return Ok(None);
            };
            read.find(tree, key)?
                .map(|id| read.descriptor(id))
                .transpose()
        }
        Transaction::Batch(batch) => storage::find_in(batch, sek, room, tree, key)?
            .map(|id| storage::descriptor_in(batch, sek, room, id))
            .transpose(),
    }
}
pub(in crate::node::channel) fn floor(
    transaction: Transaction<'_, '_>,
    sek: &Sek,
    room: &Digest32,
    key: &SessionFloorKey,
) -> Result<Option<SessionFloorBoundary>> {
    descriptor(transaction, sek, room, Tree::Floors, &floor_key(key))?
        .map(|bytes| boundary(&bytes))
        .transpose()
}

#[derive(Default, Clone, Copy)]
pub(in crate::node::channel) struct Author {
    pub announced: Option<u64>,
    pub revision: u64,
    pub through: u64,
}
impl Author {
    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 4 || d.uint()? != 1 {
            return Err(bad());
        }
        let announced = match d.array()? {
            0 => None,
            1 => Some(d.uint()?),
            _ => return Err(bad()),
        };
        let result = Self {
            announced,
            revision: d.uint()?,
            through: d.uint()?,
        };
        d.finish()?;
        Ok(result)
    }
    fn bytes(self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(1)
            .array(usize::from(self.announced.is_some()));
        if let Some(g) = self.announced {
            e.uint(g);
        }
        e.uint(self.revision).uint(self.through);
        e.finish()
    }
}
pub(in crate::node::channel) fn author(
    transaction: Transaction<'_, '_>,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
) -> Result<Author> {
    Ok(descriptor(
        transaction,
        sek,
        room,
        Tree::FloorAuthors,
        &author_key(author),
    )?
    .map(|bytes| Author::read(&bytes))
    .transpose()?
    .unwrap_or_default())
}
fn replace(index: &mut Write<'_, '_>, tree: Tree, key: Key, bytes: &[u8]) -> Result<u64> {
    let id = match index.find(tree, &key)? {
        Some(id) => {
            index.replace_descriptor(id, bytes)?;
            id
        }
        None => index.put_descriptor(bytes)?,
    };
    index.set(tree, key, Some(id))?;
    Ok(id)
}
/// The caller has authenticated and published the entry in this same Batch. Contiguous
/// progress is independent of whether it contains a floor, so an absent lookup is meaningful.
pub(super) fn observe(
    index: &mut Write<'_, '_>,
    room: &Digest32,
    entry: &crate::log::entry::Entry,
    current_epoch: u64,
) -> Result<()> {
    let author = entry.skeleton.author_id;
    let key = author_key(&author);
    let mut state = index
        .find(Tree::FloorAuthors, &key)?
        .map(|id| index.descriptor(id).and_then(|b| Author::read(&b)))
        .transpose()?
        .unwrap_or_default();
    let old_through = state.through;
    if state.through.checked_add(1) == Some(entry.skeleton.seq) {
        state.through = entry.skeleton.seq;
    }
    let mut changed = false;
    if let Some(f) = entry.payload.as_deref().and_then(Floor::read).filter(|f| {
        f.room == *room
            && f.author == author
            && f.epoch <= current_epoch
            && f.first_seq <= entry.skeleton.seq.saturating_add(1)
    }) {
        let value = (f.membership, f.iteration, f.first_seq);
        let exact = floor_key(&(author, f.recipient, f.epoch, f.generation));
        let old = index
            .find(Tree::Floors, &exact)?
            .map(|id| index.descriptor(id).and_then(|b| boundary(&b)))
            .transpose()?;
        if old.is_none_or(|old| value > old) {
            let id = replace(index, Tree::Floors, exact, &boundary_bytes(value))?;
            if author == f.recipient {
                index.set(
                    Tree::FloorSelf,
                    generation_key(&author, (f.epoch, f.generation)),
                    Some(id),
                )?;
            }
            state.announced = Some(
                state
                    .announced
                    .map_or(f.generation, |old| old.max(f.generation)),
            );
            state.revision = state.revision.checked_add(1).ok_or_else(bad)?;
            changed = true;
        }
    }
    if changed || state.through != old_through {
        replace(index, Tree::FloorAuthors, key, &state.bytes())?;
    }
    Ok(())
}

#[derive(Default)]
struct Continuity {
    revision: u64,
    membership: u64,
    before: Option<Generation>,
    upper: Option<Generation>,
    lower: Option<Generation>,
    ready: bool,
}
fn read_generation(d: &mut Decoder<'_>) -> Result<Option<Generation>> {
    match d.array()? {
        0 => Ok(None),
        2 => Ok(Some((d.uint()?, d.uint()?))),
        _ => Err(bad()),
    }
}
fn put_generation(e: &mut Encoder, value: Option<Generation>) {
    e.array(if value.is_some() { 2 } else { 0 });
    if let Some((epoch, generation)) = value {
        e.uint(epoch).uint(generation);
    }
}
impl Continuity {
    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 7 || d.uint()? != 1 {
            return Err(bad());
        }
        let result = Self {
            revision: d.uint()?,
            membership: d.uint()?,
            before: read_generation(&mut d)?,
            upper: read_generation(&mut d)?,
            lower: read_generation(&mut d)?,
            ready: match d.uint()? {
                0 => false,
                1 => true,
                _ => return Err(bad()),
            },
        };
        d.finish()?;
        Ok(result)
    }
    fn bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(7).uint(1).uint(self.revision).uint(self.membership);
        put_generation(&mut e, self.before);
        put_generation(&mut e, self.upper);
        put_generation(&mut e, self.lower);
        e.uint(u64::from(self.ready));
        e.finish()
    }
}
/// At most 64 self-generations are examined. A pending result is neither permission nor a
/// denial: callers retain their work/donor cursor and retry. The completed range is inclusive;
/// a later grant may read its own generation at its exact floor, but never generations before it.
pub(in crate::node::channel) fn continuity_step(
    store: &Store,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
    recipient: &Digest32,
    membership: u64,
) -> Result<Option<Option<(Generation, Generation)>>> {
    let mut batch = store.batch()?;
    batch.derived();
    let mut index = Write::open(&mut batch, sek, room)?;
    let state = index
        .find(Tree::FloorAuthors, &author_key(author))?
        .map(|id| index.descriptor(id).and_then(|b| Author::read(&b)))
        .transpose()?
        .unwrap_or_default();
    let key = author_key(&pair(author, recipient));
    let mut work = index
        .find(Tree::FloorContinuity, &key)?
        .map(|id| index.descriptor(id).and_then(|b| Continuity::read(&b)))
        .transpose()?
        .unwrap_or_default();
    if work.revision != state.revision || work.membership != membership {
        work = Continuity {
            revision: state.revision,
            membership,
            ..Default::default()
        };
    }
    if !work.ready {
        for _ in 0..64 {
            let before = match work.before {
                Some(g) => generation_key(author, g),
                None => {
                    let mut k = author_key(author);
                    k[32..].fill(u8::MAX);
                    k
                }
            };
            let Some((position, id)) = index
                .previous(Tree::FloorSelf, Some(before))?
                .filter(|(k, _)| k[..32] == author[..])
            else {
                work.ready = true;
                work.lower = work.upper.map(|_| (0, 0));
                break;
            };
            let g = generation(&position);
            let (_, _, author_start) = boundary(&index.descriptor(id)?)?;
            work.upper.get_or_insert(g);
            work.before = Some(g);
            let exact = floor_key(&(*author, *recipient, g.0, g.1));
            let target = index
                .find(Tree::Floors, &exact)?
                .map(|id| index.descriptor(id).and_then(|b| boundary(&b)))
                .transpose()?;
            if target
                .is_none_or(|(m, from, first)| m != membership || from != 0 || first > author_start)
            {
                work.lower = Some(g);
                work.ready = true;
                break;
            }
        }
        replace(&mut index, Tree::FloorContinuity, key, &work.bytes())?;
        index.seal()?;
        batch.commit()?;
    }
    Ok(work.ready.then(|| work.lower.zip(work.upper)))
}

/// Resume an own-feed search without retaining entries. This is only used while publishing
/// an absent/advanced grant, never for each Session body. A found first sequence is immutable.
#[allow(clippy::too_many_arguments)]
pub(in crate::node::channel) fn first_sequence(
    store: &Store,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
    epoch: u64,
    generation: u64,
    iteration: u64,
    head: u64,
    mut entry_at: impl FnMut(u64) -> Result<crate::log::entry::Entry>,
) -> Result<Option<Option<u64>>> {
    let mut key = generation_key(author, (epoch, generation));
    key[48..56].copy_from_slice(&iteration.to_be_bytes());
    let (mut after, mut found) = match descriptor(
        Transaction::Snapshot(&store.snapshot()?),
        sek,
        room,
        Tree::FloorFirst,
        &key,
    )? {
        None => (0, None),
        Some(bytes) => {
            let mut d = Decoder::new(&bytes);
            if d.array()? != 3 || d.uint()? != 1 {
                return Err(bad());
            }
            let after = d.uint()?;
            let found = match d.array()? {
                0 => None,
                1 => Some(d.uint()?),
                _ => return Err(bad()),
            };
            d.finish()?;
            (after, found)
        }
    };
    if found.is_some() {
        return Ok(Some(found));
    }
    let mut bytes = 0usize;
    for _ in 0..64 {
        if after >= head {
            break;
        }
        let seq = after.checked_add(1).ok_or_else(bad)?;
        let entry = entry_at(seq)?;
        let size = entry.payload.as_ref().map_or(0, Vec::len);
        if bytes != 0 && bytes.saturating_add(size) > 1024 * 1024 {
            break;
        }
        bytes = bytes.saturating_add(size);
        if entry
            .payload
            .as_deref()
            .and_then(|p| crate::group::message::GroupMessage::from_wire(p).ok())
            .is_some_and(|m| {
                m.header.channel_id == crate::node::drive::drive_channel(room)
                    && m.header.epoch == epoch
                    && m.header.chain_id == generation
                    && m.header.iteration >= iteration
            })
        {
            found = Some(seq);
        }
        after = seq;
        if found.is_some() {
            break;
        }
    }
    let mut e = Encoder::new();
    e.array(3)
        .uint(1)
        .uint(after)
        .array(usize::from(found.is_some()));
    if let Some(seq) = found {
        e.uint(seq);
    }
    let mut batch = store.batch()?;
    batch.derived();
    let mut index = Write::open(&mut batch, sek, room)?;
    replace(&mut index, Tree::FloorFirst, key, &e.finish())?;
    index.seal()?;
    batch.commit()?;
    Ok((found.is_some() || after >= head).then_some(found))
}
