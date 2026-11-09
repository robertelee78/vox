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
    Ok(stored(bytes)?.0)
}
/// A retained floor and the author sequence that signed it. A record written before the
/// sequence was kept has none; the source replay restarted for it rewrites every such record.
fn stored(bytes: &[u8]) -> Result<(SessionFloorBoundary, Option<u64>)> {
    let mut d = Decoder::new(bytes);
    let arity = d.array()?;
    if !matches!(arity, 4 | 5) || d.uint()? != 1 {
        return Err(bad());
    }
    let value = (d.uint()?, d.uint()?, d.uint()?);
    let signed = if arity == 5 { Some(d.uint()?) } else { None };
    d.finish()?;
    Ok((value, signed))
}
fn boundary_bytes(value: SessionFloorBoundary, signed: u64) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .uint(1)
        .uint(value.0)
        .uint(value.1)
        .uint(value.2)
        .uint(signed);
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
/// Every retained floor `author` published for `recipient`, by (epoch, generation).
pub(in crate::node::channel) fn floors_for(
    snapshot: &crate::node::store::Snapshot,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
    recipient: &Digest32,
) -> Result<Vec<(Generation, SessionFloorBoundary)>> {
    let Some(read) = Read::existing(snapshot, sek, room)? else {
        return Ok(Vec::new());
    };
    let start = author_key(&pair(author, recipient));
    let mut floors = Vec::new();
    let mut row = read.find(Tree::Floors, &start)?.map(|id| (start, id));
    if row.is_none() {
        row = read.next(Tree::Floors, Some(start))?;
    }
    while let Some((key, id)) = row.filter(|(key, _)| key[..32] == start[..32]) {
        floors.push((generation(&key), boundary(&read.descriptor(id)?)?));
        row = read.next(Tree::Floors, Some(key))?;
    }
    Ok(floors)
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
/// Reconstruction is independent of folded maxima: each source is recovered from
/// the already authenticated public log and its cursor commits with its locator.
/// A cursor of the first form folded floors without their signing sequence: the replay
/// starts again, so each retained floor is decided by its later-signed source.
pub(in crate::node::channel) fn source_replay(
    transaction: Transaction<'_, '_>,
    sek: &Sek,
    room: &Digest32,
) -> Result<(u64, bool)> {
    let Some(bytes) = descriptor(transaction, sek, room, Tree::FloorReplay, &[0; 64])? else {
        return Ok((0, false));
    };
    let mut d = Decoder::new(&bytes);
    if d.array()? != 3 {
        return Err(bad());
    }
    let version = d.uint()?;
    if !matches!(version, 1 | 2) {
        return Err(bad());
    }
    let after = d.uint()?;
    let done = match d.uint()? {
        0 => false,
        1 => true,
        _ => return Err(bad()),
    };
    d.finish()?;
    Ok(if version == 1 {
        (0, false)
    } else {
        (after, done)
    })
}

pub(in crate::node::channel) fn save_source_replay(
    batch: &mut crate::node::store::Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    after: u64,
    done: bool,
) -> Result<()> {
    let mut e = Encoder::new();
    e.array(3).uint(2).uint(after).uint(u64::from(done));
    let mut index = Write::open(batch, sek, room)?;
    replace(&mut index, Tree::FloorReplay, [0; 64], &e.finish())?;
    index.seal()
}

/// The next retained signed floor source in this author's feed.
pub(in crate::node::channel) fn source_after(
    snapshot: &crate::node::store::Snapshot,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
    after: u64,
) -> Result<Option<(u64, Digest32)>> {
    let Some(read) = Read::existing(snapshot, sek, room)? else {
        return Ok(None);
    };
    let mut key = author_key(author);
    key[32..40].copy_from_slice(&after.to_be_bytes());
    let Some((key, id)) = read
        .next(Tree::FloorSources, Some(key))?
        .filter(|(key, _)| key[..32] == author[..])
    else {
        return Ok(None);
    };
    if key[40..].iter().any(|byte| *byte != 0) {
        return Err(bad());
    }
    let seq = u64::from_be_bytes(key[32..40].try_into().map_err(|_| bad())?);
    let hash = read
        .descriptor(id)?
        .as_slice()
        .try_into()
        .map_err(|_| bad())?;
    Ok(Some((seq, hash)))
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
        // Keep the identity of every signed statement, not merely the largest folded
        // boundary. Removal/readmission authorization depends on its causal ancestry.
        let mut source = author_key(&author);
        source[32..40].copy_from_slice(&entry.skeleton.seq.to_be_bytes());
        let hash = entry.entry_hash();
        if let Some(id) = index.find(Tree::FloorSources, &source)? {
            if index.descriptor(id)?.as_slice() != hash {
                return Err(bad());
            }
        } else {
            replace(index, Tree::FloorSources, source, &hash)?;
            changed = true;
        }
        let value = (f.membership, f.iteration, f.first_seq);
        let signed = entry.skeleton.seq;
        let exact = floor_key(&(author, f.recipient, f.epoch, f.generation));
        let old = index
            .find(Tree::Floors, &exact)?
            .map(|id| index.descriptor(id).and_then(|b| stored(&b)))
            .transpose()?;
        // The later-signed floor decides the recipient's membership on this key, whatever
        // order its sources arrive or replay in; within one membership the largest boundary
        // stands. A record without its signing sequence is rewritten by the source replay.
        let next = match old {
            None | Some((_, None)) => Some((value, signed)),
            Some((old, Some(at))) if old.0 == value.0 => {
                let next = (old.max(value), at.max(signed));
                (next != (old, at)).then_some(next)
            }
            Some((_, Some(at))) => (signed > at).then_some((value, signed)),
        };
        if let Some((value, signed)) = next {
            let id = replace(index, Tree::Floors, exact, &boundary_bytes(value, signed))?;
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
            changed = true;
        }
    }
    if changed {
        state.revision = state.revision.checked_add(1).ok_or_else(bad)?;
    }
    if changed || state.through != old_through {
        replace(index, Tree::FloorAuthors, key, &state.bytes())?;
    }
    Ok(())
}
#[derive(Default)]
struct FloorProof {
    generation: u64,
    revision: u64,
    phase: u64,
    after_removal: Option<Digest32>,
    removal: Option<Digest32>,
    after_restoration: Option<Digest32>,
    restoration: Option<Digest32>,
    after_source: u64,
}

fn proof_hash(d: &mut Decoder<'_>) -> Result<Option<Digest32>> {
    let bytes = d.bytes()?;
    if bytes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(bytes.try_into().map_err(|_| bad())?))
    }
}

fn put_proof_hash(e: &mut Encoder, hash: Option<Digest32>) {
    e.bytes(hash.as_ref().map_or(&[][..], |hash| &hash[..]));
}

impl FloorProof {
    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 9 || d.uint()? != 1 {
            return Err(bad());
        }
        let state = Self {
            generation: d.uint()?,
            revision: d.uint()?,
            phase: d.uint()?,
            after_removal: proof_hash(&mut d)?,
            removal: proof_hash(&mut d)?,
            after_restoration: proof_hash(&mut d)?,
            restoration: proof_hash(&mut d)?,
            after_source: d.uint()?,
        };
        d.finish()?;
        if state.phase > 4 {
            return Err(bad());
        }
        Ok(state)
    }
    fn bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(9)
            .uint(1)
            .uint(self.generation)
            .uint(self.revision)
            .uint(self.phase);
        put_proof_hash(&mut e, self.after_removal);
        put_proof_hash(&mut e, self.removal);
        put_proof_hash(&mut e, self.after_restoration);
        put_proof_hash(&mut e, self.restoration);
        e.uint(self.after_source);
        e.finish()
    }
}

/// One bounded proof turn for a signed floor. It retains the source hash and
/// checks every covering creator restoration against every earlier floor generation.
pub(in crate::node::channel) fn authorization_step(
    store: &Store,
    sek: &Sek,
    room: &Digest32,
    root: Digest32,
    now: u64,
    entry: &crate::log::entry::Entry,
    recipient_current: bool,
) -> Result<Option<bool>> {
    use crate::governance::entry::{GovBody, GovEntry};
    use crate::node::channel::governance::{ContentEligibility, View};
    let floor = entry
        .payload
        .as_deref()
        .and_then(Floor::read)
        .ok_or_else(bad)?;
    if floor.room != *room
        || floor.author != entry.skeleton.author_id
        || floor.epoch != entry.skeleton.epoch
    {
        return Err(bad());
    }
    let snapshot = store.snapshot()?;
    let view = View::pinned(&snapshot, sek, room, root, now)?;
    match view.floor_recipient_eligibility(entry)? {
        ContentEligibility::Eligible => {}
        ContentEligibility::Ineligible => return Ok(Some(false)),
        ContentEligibility::Refreshing => return Ok(None),
    }
    let generation = view.authority_generation();
    let revision = author(Transaction::Snapshot(&snapshot), sek, room, &floor.author)?.revision;
    let mut key = author_key(&entry.entry_hash());
    key[63] = u8::from(recipient_current);
    let mut state = descriptor(
        Transaction::Snapshot(&snapshot),
        sek,
        room,
        Tree::FloorAuthorization,
        &key,
    )?
    .map(|bytes| FloorProof::read(&bytes))
    .transpose()?
    .unwrap_or_default();
    if state.generation != generation || state.revision != revision {
        state = FloorProof {
            generation,
            revision,
            ..Default::default()
        };
    }
    for _ in 0..64 {
        match state.phase {
            0 => {
                let target = if recipient_current {
                    &floor.recipient
                } else {
                    &floor.author
                };
                let Some((hash, removal)) =
                    view.member_fact_after(target, false, state.after_removal)?
                else {
                    state.phase = 3;
                    break;
                };
                state.after_removal = Some(hash);
                let Some(_removal) = removal else {
                    continue;
                };
                // New private records need a restored floor even if the floor
                // predates the cut: private bytes have no public causal position.
                state.removal = Some(hash);
                state.after_restoration = None;
                state.phase = 1;
            }
            1 => {
                let target = if recipient_current {
                    &floor.recipient
                } else {
                    &floor.author
                };
                let Some((hash, restoration)) =
                    view.member_fact_after(target, true, state.after_restoration)?
                else {
                    state.phase = 4;
                    break;
                };
                state.after_restoration = Some(hash);
                let Some(restoration) = restoration else {
                    continue;
                };
                let GovBody::MemberReadmission(body) = GovEntry::body_bound_to(&restoration)?
                else {
                    return Err(bad());
                };
                if body
                    .removal_entry_hashes
                    .binary_search(&state.removal.ok_or_else(bad)?)
                    .is_err()
                {
                    continue;
                }
                match view.causal_contains(&entry.entry_hash(), &restoration)? {
                    Some(true) => {}
                    Some(false) => continue,
                    None => return Ok(None),
                }
                if recipient_current {
                    state.phase = 0;
                    state.removal = None;
                    continue;
                }
                state.restoration = Some(hash);
                state.after_source = 0;
                state.phase = 2;
            }
            2 => {
                let Some((seq, hash)) =
                    source_after(&snapshot, sek, room, &floor.author, state.after_source)?
                else {
                    state.phase = 0;
                    state.removal = None;
                    state.restoration = None;
                    continue;
                };
                state.after_source = seq;
                let Some(other) = view.source(&hash)? else {
                    return Ok(None);
                };
                let Some(other_floor) = other.payload.as_deref().and_then(Floor::read) else {
                    return Err(bad());
                };
                if other_floor.generation < floor.generation {
                    continue;
                }
                match view.causal_contains(
                    &other.entry_hash(),
                    &view
                        .source(&state.restoration.ok_or_else(bad)?)?
                        .ok_or_else(bad)?,
                )? {
                    Some(true) => {}
                    Some(false) => {
                        state.phase = 1;
                        state.restoration = None;
                    }
                    None => return Ok(None),
                }
            }
            3 => return Ok(Some(true)),
            4 => return Ok(Some(false)),
            _ => return Err(bad()),
        }
    }
    drop(view);
    drop(snapshot);
    let mut batch = store.batch()?;
    batch.derived();
    {
        let view = View::in_batch(&batch, sek, room, root, now)?;
        if view.authority_generation() != generation {
            return Ok(None);
        }
        if author(Transaction::Batch(&batch), sek, room, &floor.author)?.revision != revision {
            return Ok(None);
        }
    }
    let mut index = Write::open(&mut batch, sek, room)?;
    replace(&mut index, Tree::FloorAuthorization, key, &state.bytes())?;
    index.seal()?;
    batch.commit()?;
    Ok(match state.phase {
        3 => Some(true),
        4 => Some(false),
        _ => None,
    })
}

#[derive(Default)]
struct FloorSelection {
    generation: u64,
    revision: u64,
    membership: u64,
    after: u64,
    done: bool,
    best: Option<(u64, u64)>,
}
impl FloorSelection {
    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 7 || d.uint()? != 1 {
            return Err(bad());
        }
        let generation = d.uint()?;
        let revision = d.uint()?;
        let membership = d.uint()?;
        let after = d.uint()?;
        let done = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(bad()),
        };
        let best = match d.array()? {
            0 => None,
            2 => Some((d.uint()?, d.uint()?)),
            _ => return Err(bad()),
        };
        d.finish()?;
        Ok(Self {
            generation,
            revision,
            membership,
            after,
            done,
            best,
        })
    }
    fn bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(7)
            .uint(1)
            .uint(self.generation)
            .uint(self.revision)
            .uint(self.membership)
            .uint(self.after)
            .uint(u64::from(self.done));
        e.array(if self.best.is_some() { 2 } else { 0 });
        if let Some((iteration, first)) = self.best {
            e.uint(iteration).uint(first);
        }
        e.finish()
    }
}

/// Resolve an exact recipient/generation floor from authenticated source entries.
/// The returned boundary is published only after the bounded scan completes.
#[allow(clippy::too_many_arguments)]
pub(in crate::node::channel) fn authorized_floor_step(
    store: &Store,
    sek: &Sek,
    room: &Digest32,
    root: Digest32,
    now: u64,
    key: &SessionFloorKey,
    membership: u64,
    recipient_current: bool,
) -> Result<Option<Option<SessionFloorBoundary>>> {
    use crate::node::channel::governance::View;
    let snapshot = store.snapshot()?;
    let view = View::pinned(&snapshot, sek, room, root, now)?;
    let generation = view.authority_generation();
    let revision = author(Transaction::Snapshot(&snapshot), sek, room, &key.0)?.revision;
    let mut tree_key = floor_key(key);
    // One bounded selection per queried membership: a corrected start's two lookups on one
    // key (at the current and at the retained membership) never restart each other's scan.
    tree_key[48..56].copy_from_slice(&membership.to_be_bytes());
    tree_key[63] = u8::from(recipient_current);
    let mut state = descriptor(
        Transaction::Snapshot(&snapshot),
        sek,
        room,
        Tree::FloorSelection,
        &tree_key,
    )?
    .map(|bytes| FloorSelection::read(&bytes))
    .transpose()?
    .unwrap_or_default();
    if state.generation != generation
        || state.revision != revision
        || state.membership != membership
    {
        state = FloorSelection {
            generation,
            revision,
            membership,
            ..Default::default()
        };
    }
    if state.done {
        return Ok(Some(
            state
                .best
                .map(|(iteration, first)| (membership, iteration, first)),
        ));
    }
    for _ in 0..64 {
        let Some((seq, hash)) = source_after(&snapshot, sek, room, &key.0, state.after)? else {
            state.done = true;
            break;
        };
        let Some(entry) = view.source(&hash)? else {
            return Ok(None);
        };
        let floor = entry
            .payload
            .as_deref()
            .and_then(Floor::read)
            .ok_or_else(bad)?;
        if (floor.author, floor.recipient, floor.epoch, floor.generation) == *key
            && floor.membership == membership
        {
            match authorization_step(store, sek, room, root, now, &entry, false)? {
                Some(true) => {
                    if recipient_current {
                        match authorization_step(store, sek, room, root, now, &entry, true)? {
                            Some(true) => {}
                            Some(false) => {
                                state.after = seq;
                                continue;
                            }
                            None => break,
                        }
                    }
                    let boundary = (floor.iteration, floor.first_seq);
                    if state.best.is_none_or(|old| boundary < old) {
                        state.best = Some(boundary);
                    }
                }
                Some(false) => {}
                None => break,
            }
        }
        state.after = seq;
    }
    drop(view);
    drop(snapshot);
    let mut batch = store.batch()?;
    batch.derived();
    {
        let view = View::in_batch(&batch, sek, room, root, now)?;
        if view.authority_generation() != generation {
            return Ok(None);
        }
        if author(Transaction::Batch(&batch), sek, room, &key.0)?.revision != revision {
            return Ok(None);
        }
    }
    let mut index = Write::open(&mut batch, sek, room)?;
    replace(&mut index, Tree::FloorSelection, tree_key, &state.bytes())?;
    index.seal()?;
    batch.commit()?;
    Ok(state.done.then_some(
        state
            .best
            .map(|(iteration, first)| (membership, iteration, first)),
    ))
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
