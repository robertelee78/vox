//! Private wire/cache records remain in PrivateSession. This catalog holds only sealed
//! locators, updated in the same transaction as the authenticated wire and ratchet state.

use crate::atrest::sek::Sek;
use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::store::{Batch, Snapshot};

use super::super::private_session::Stored;
use super::record::{Descriptor, EnvelopeRef, Key, Part, Position, Source};
use super::storage::{Read, Tree, Write};

// This small checkpoint certifies the existing private locator roots. It is committed
// with each verified row/index write, never ahead of the effects it acknowledges.
const RESTART: u64 = 22;

#[derive(Clone, Default)]
pub(in crate::node::channel) struct Restart {
    pub complete: bool,
    pub after: Option<u64>,
    pub next: u64,
    pub pending: bool,
    pub pending_after: Option<u64>,
    pub pending_through: u64,
}

impl Restart {
    fn read(sek: &Sek, segment: &crate::atrest::store::SealedSegment) -> Result<Self> {
        if segment.ciphertext.len() > 256 {
            return Err(Error::MalformedAtRest("private restart size"));
        }
        let bytes = open_segment(sek, SegmentKind::KeyMaterial, RESTART, segment)?;
        let mut d = Decoder::new(&bytes);
        if d.array()? != 7 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("private restart version"));
        }
        let complete = flag(&mut d)?;
        let after = optional(&mut d)?;
        let next = d.uint()?;
        let pending = flag(&mut d)?;
        let pending_after = optional(&mut d)?;
        let pending_through = d.uint()?;
        d.finish()?;
        if next == 0
            || after.is_some_and(|id| id >= next)
            || pending_through > next
            || pending_after.is_some_and(|id| id >= pending_through)
        {
            return Err(Error::MalformedAtRest("private restart cursor"));
        }
        Ok(Self {
            complete,
            after,
            next,
            pending,
            pending_after,
            pending_through,
        })
    }
    pub fn queue(&self, batch: &mut Batch<'_>, sek: &Sek, room: &Digest32) -> Result<()> {
        if self.complete && !super::storage::exists_in(batch, room)? {
            // Empty new rooms have no locator writes yet. Publish their empty index with
            // this checkpoint; saved bodies without an index are never certified complete.
            if batch
                .last_segment_id(room, SegmentKind::PrivateSession)?
                .is_some()
            {
                return Err(Error::MalformedAtRest("private restart index missing"));
            }
            Write::open(batch, sek, room)?.seal()?;
        }
        let mut e = Encoder::new();
        e.array(7).uint(1).uint(u64::from(self.complete));
        put_optional(&mut e, self.after);
        e.uint(self.next.max(1)).uint(u64::from(self.pending));
        put_optional(&mut e, self.pending_after);
        e.uint(self.pending_through);
        let segment = seal_segment(sek, SegmentKind::KeyMaterial, RESTART, &e.finish())?;
        batch.put_segment(room, SegmentKind::KeyMaterial, RESTART, &segment)
    }
}
fn flag(d: &mut Decoder<'_>) -> Result<bool> {
    match d.uint()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::MalformedAtRest("private restart flag")),
    }
}
fn optional(d: &mut Decoder<'_>) -> Result<Option<u64>> {
    match d.array()? {
        0 => Ok(None),
        1 => Ok(Some(d.uint()?)),
        _ => Err(Error::MalformedAtRest("private restart optional cursor")),
    }
}
fn put_optional(e: &mut Encoder, value: Option<u64>) {
    e.array(usize::from(value.is_some()));
    if let Some(value) = value {
        e.uint(value);
    }
}
pub(in crate::node::channel) fn restart(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
) -> Result<Restart> {
    let state = snapshot
        .get_segment(room, SegmentKind::KeyMaterial, RESTART)?
        .map(|s| Restart::read(sek, &s))
        .transpose()?
        .unwrap_or_else(|| Restart {
            next: 1,
            ..Default::default()
        });
    if state.complete && Read::existing(snapshot, sek, room)?.is_none() {
        return Err(Error::MalformedAtRest("private restart index missing"));
    }
    Ok(state)
}

/// Fresh create/join already has an empty room transaction; certify that exact empty index.
pub(in crate::node::channel) fn initialize(
    batch: &mut Batch<'_>,
    sek: &Sek,
    room: &Digest32,
) -> Result<()> {
    if batch
        .last_segment_id(room, SegmentKind::PrivateSession)?
        .is_some()
    {
        return Err(Error::MalformedAtRest(
            "private initialization is not empty",
        ));
    }
    Restart {
        complete: true,
        next: 1,
        ..Default::default()
    }
    .queue(batch, sek, room)
}

fn restart_in(batch: &Batch<'_>, sek: &Sek, room: &Digest32) -> Result<Restart> {
    batch
        .get_segment(room, SegmentKind::KeyMaterial, RESTART)?
        .map(|s| Restart::read(sek, &s))
        .transpose()
        .map(|s| {
            s.unwrap_or_else(|| Restart {
                next: 1,
                ..Default::default()
            })
        })
}
pub(in crate::node::channel) fn unread_after(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    after: Option<u64>,
) -> Result<Option<u64>> {
    let Some(read) = Read::existing(snapshot, sek, room)? else {
        return Ok(None);
    };
    read.next(Tree::PrivateUnread, after.map(arrival_key))
        .map(|v| v.map(|(_, id)| id))
}

fn hash_key(hash: &Digest32) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(hash);
    key
}

fn arrival_key(id: u64) -> Key {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&id.to_be_bytes());
    key
}

pub(in crate::node::channel) fn find(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    hash: &Digest32,
) -> Result<Option<u64>> {
    match Read::existing(snapshot, sek, room)? {
        Some(read) => read.find(Tree::PrivateHash, &hash_key(hash)),
        None => Ok(None),
    }
}

pub(in crate::node::channel) fn find_in(
    batch: &Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    hash: &Digest32,
) -> Result<Option<u64>> {
    super::storage::find_in(batch, sek, room, Tree::PrivateHash, &hash_key(hash))
}

/// Exact logical lifecycle content. The row remains authoritative; this fixed locator only
/// avoids scanning every retained private record before refreshing one grant.
fn refresh_key(author: &Digest32, created: u64, body: &str) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(author);
    key[32..].copy_from_slice(&crate::hash::sha256_concat(&[
        b"vox/private-session-refresh/v1",
        &created.to_be_bytes(),
        body.as_bytes(),
    ]));
    key
}

pub(in crate::node::channel) fn matching_lifecycle(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
    created: u64,
    body: &str,
) -> Result<Option<u64>> {
    match Read::existing(snapshot, sek, room)? {
        Some(read) => read.find(Tree::RefreshRecords, &refresh_key(author, created, body)),
        None => Ok(None),
    }
}

pub(in crate::node::channel) fn candidate_after(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    after: Option<Key>,
) -> Result<Option<(Key, u64)>> {
    let Some(read) = Read::existing(snapshot, sek, room)? else {
        return Ok(None);
    };
    let Some((key, descriptor)) = read.next(Tree::Candidates, after)? else {
        return Ok(None);
    };
    let bytes = read.descriptor(descriptor)?;
    let mut d = crate::cbor::Decoder::new(&bytes);
    let source = Source::read(&mut d)?;
    d.finish()?;
    if !source.position.private || source.position.key() != key {
        return Err(Error::MalformedAtRest("private Session candidate binding"));
    }
    Ok(Some((key, source.id)))
}

pub(in crate::node::channel) fn lifecycle_revision(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
) -> Result<u64> {
    Ok(Read::existing(snapshot, sek, room)?.map_or(0, |r| r.header.private_generation))
}

fn age(saved: &Stored, id: u64) -> (Tree, Key) {
    let lifecycle = saved
        .row
        .as_ref()
        .is_some_and(|r| crate::node::sessions::is_record(&r.body));
    let claimed = saved
        .row
        .as_ref()
        .map(|r| r.created_millis)
        .or_else(|| saved.record.legacy_claimed_ms())
        .unwrap_or(saved.first_seen);
    let mut key = [0; 64];
    key[..8].copy_from_slice(&saved.first_seen.min(claimed).to_be_bytes());
    key[8..16].copy_from_slice(&id.to_be_bytes());
    (
        if lifecycle {
            Tree::PrivateAge
        } else {
            Tree::PrivateStepAge
        },
        key,
    )
}

pub(in crate::node::channel) fn next_expired(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    now: u64,
    ttl: u64,
    step_ttl: u64,
) -> Result<Option<u64>> {
    let Some(read) = Read::existing(snapshot, sek, room)? else {
        return Ok(None);
    };
    for (tree, ttl) in [(Tree::PrivateAge, ttl), (Tree::PrivateStepAge, step_ttl)] {
        if ttl == 0 {
            continue;
        }
        if let Some((key, id)) = read.next(tree, None)? {
            let base = u64::from_be_bytes(
                key[..8]
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("Session age key"))?,
            );
            let indexed = u64::from_be_bytes(
                key[8..16]
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("Session age locator"))?,
            );
            if indexed != id {
                return Err(Error::MalformedAtRest("Session age locator differs"));
            }
            if base <= now.saturating_sub(ttl.saturating_mul(1000)) {
                return Ok(Some(id));
            }
        }
    }
    Ok(None)
}

/// Authenticated observations only. A generation is never a permission or key, and expiry
/// cannot lower it. `through` distinguishes a complete negative lookup from pending repair.
#[derive(Default, Clone, Copy)]
pub(in crate::node::channel) struct Control {
    pub generation: Option<u64>,
    pub support: Option<Digest32>,
    pub through: u64,
}
impl Control {
    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = crate::cbor::Decoder::new(bytes);
        if d.array()? != 4 || d.uint()? != 1 {
            return Err(Error::MalformedAtRest("Session control fact"));
        }
        let generation = match d.array()? {
            0 => None,
            1 => Some(d.uint()?),
            _ => return Err(Error::MalformedAtRest("Session generation fact")),
        };
        let support = match d.bytes()? {
            [] => None,
            b => Some(
                b.try_into()
                    .map_err(|_| Error::MalformedAtRest("Session support fact"))?,
            ),
        };
        let through = d.uint()?;
        d.finish()?;
        Ok(Self {
            generation,
            support,
            through,
        })
    }
    fn bytes(self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(1)
            .array(usize::from(self.generation.is_some()));
        if let Some(generation) = self.generation {
            e.uint(generation);
        }
        e.bytes(self.support.as_ref().map_or(&[][..], |h| &h[..]))
            .uint(self.through);
        e.finish()
    }
}

pub(in crate::node::channel) fn control(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
) -> Result<Control> {
    let Some(read) = Read::existing(snapshot, sek, room)? else {
        return Ok(Control::default());
    };
    let Some(id) = read.find(Tree::Controls, &hash_key(author))? else {
        return Ok(Control::default());
    };
    Control::read(&read.descriptor(id)?)
}

pub(in crate::node::channel) fn control_in(
    batch: &Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
) -> Result<Control> {
    let Some(id) = super::storage::find_in(batch, sek, room, Tree::Controls, &hash_key(author))?
    else {
        return Ok(Control::default());
    };
    let sealed = batch
        .get_segment(room, crate::atrest::store::SegmentKind::SessionIndex, id)?
        .ok_or(Error::MalformedAtRest("Session control descriptor missing"))?;
    if sealed.ciphertext.len() > 128 + crate::atrest::sek::TAG_LEN {
        return Err(Error::MalformedAtRest("Session control descriptor size"));
    }
    Control::read(&crate::atrest::store::open_segment(
        sek,
        crate::atrest::store::SegmentKind::SessionIndex,
        id,
        &sealed,
    )?)
}

fn merge_control(index: &mut Write<'_, '_>, author: &Digest32, seen: Control) -> Result<()> {
    let key = hash_key(author);
    let old_id = index.find(Tree::Controls, &key)?;
    let old = old_id
        .map(|id| index.descriptor(id).and_then(|bytes| Control::read(&bytes)))
        .transpose()?
        .unwrap_or_default();
    let merged = Control {
        generation: old.generation.into_iter().chain(seen.generation).max(),
        support: old.support.or(seen.support),
        through: old.through.max(seen.through),
    };
    if old.generation == merged.generation
        && old.support == merged.support
        && old.through == merged.through
    {
        return Ok(());
    }
    let id = match old_id {
        Some(id) => {
            index.replace_descriptor(id, &merged.bytes())?;
            id
        }
        None => index.put_descriptor(&merged.bytes())?,
    };
    index.set(Tree::Controls, key, Some(id))
}

pub(in crate::node::channel) fn observe_control(
    batch: &mut Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
    seen: Control,
) -> Result<()> {
    let mut index = Write::open(batch, sek, room)?;
    merge_control(&mut index, author, seen)?;
    index.seal()
}

/// Caller has authenticated this exact entry and publishes it in the same Batch. This helper
/// must never run on an unpublished promotion chunk. Bodyless gaps are caught up separately.
pub(in crate::node::channel) fn observe_public(
    batch: &mut Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    entry: &crate::log::entry::Entry,
    current_epoch: u64,
) -> Result<()> {
    if entry.skeleton.channel_id != *room {
        return Err(Error::MalformedAtRest("Session control room binding"));
    }
    let author = entry.skeleton.author_id;
    let mut index = Write::open(batch, sek, room)?;
    let old = index
        .find(Tree::Controls, &hash_key(&author))?
        .map(|id| index.descriptor(id).and_then(|bytes| Control::read(&bytes)))
        .transpose()?
        .unwrap_or_default();
    let mut seen = Control::default();
    if old.through.checked_add(1) == Some(entry.skeleton.seq) {
        seen.through = entry.skeleton.seq;
    }
    if let Some(body) = &entry.payload {
        if body.as_slice() == super::super::private_session::support_body(room, &author) {
            seen.support = Some(entry.entry_hash());
        }
        if let Ok(message) = crate::group::message::GroupMessage::from_wire(body) {
            if message.header.channel_id == crate::node::drive::drive_channel(room)
                && message.header.author_id == author
                && message.header.epoch == entry.skeleton.epoch
            {
                seen.generation = Some(message.header.chain_id);
            }
        }
    }
    merge_control(&mut index, &author, seen)?;
    super::floor_index::observe(&mut index, room, entry, current_epoch)?;
    index.seal()
}

fn candidate(saved: &Stored, id: u64) -> Option<Source> {
    let row = saved.row.as_ref()?;
    if !crate::node::sessions::is_record(&row.body) && !row.body.contains("session_name") {
        return None;
    }
    Some(Source {
        position: Position {
            created: row.created_millis,
            private: true,
            order: id,
            hash: row.entry_hash,
        },
        author: row.author,
        id,
    })
}

/// Called while the original PrivateSession record and any receiver-chain advancement are
/// still queued in this Batch. No reader can see a locator without the matching saved row.
pub(in crate::node::channel) fn put(
    batch: &mut Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    id: u64,
    saved: &Stored,
) -> Result<()> {
    let mut index = Write::open(batch, sek, room)?;
    index.header.activity_generation =
        index
            .header
            .activity_generation
            .checked_add(1)
            .ok_or(Error::MalformedAtRest(
                "Session activity revision exhausted",
            ))?;
    merge_control(
        &mut index,
        &saved.record.message.header.author_id,
        Control {
            generation: Some(saved.record.message.header.chain_id),
            ..Control::default()
        },
    )?;
    let hash = saved.record.hash();
    if id == 0 {
        return Err(Error::MalformedAtRest("private Session id is zero"));
    }
    if index
        .find(Tree::PrivateHash, &hash_key(&hash))?
        .is_some_and(|old| old != id)
    {
        return Err(Error::MalformedAtRest(
            "private Session hash has two locators",
        ));
    }
    let (tree, key) = age(saved, id);
    index.set(tree, key, Some(id))?;
    index.set(Tree::PrivateHash, hash_key(&hash), Some(id))?;
    index.set(Tree::PrivateArrival, arrival_key(id), Some(id))?;
    index.set(
        Tree::PrivateUnread,
        arrival_key(id),
        saved.row.is_none().then_some(id),
    )?;
    if let Some(row) = saved
        .row
        .as_ref()
        .filter(|r| crate::node::sessions::is_record(&r.body))
    {
        let key = refresh_key(&row.author, row.created_millis, &row.body);
        if index
            .find(Tree::RefreshRecords, &key)?
            .is_none_or(|old| old <= id)
        {
            index.set(Tree::RefreshRecords, key, Some(id))?;
        }
    }
    if let Some(source) = candidate(saved, id) {
        index.header.private_generation =
            index
                .header
                .private_generation
                .checked_add(1)
                .ok_or(Error::MalformedAtRest(
                    "Session candidate revision exhausted",
                ))?;
        let key = source.position.key();
        if let Some(old) = index.find(Tree::Candidates, &key)? {
            index.delete_descriptor(old)?;
        }
        let mut e = Encoder::new();
        source.put(&mut e);
        let descriptor = index.put_descriptor(&e.finish())?;
        index.set(Tree::Candidates, key, Some(descriptor))?;
    }
    if let Some(row) = saved
        .row
        .as_ref()
        .filter(|row| crate::node::drive::is_file_out(row))
    {
        index.set(Tree::Files, arrival_key(id), Some(id))?;
        if hash != row.entry_hash {
            return Err(Error::MalformedAtRest("Session file hash binding"));
        }
    }
    if let Some(row) = &saved.row {
        super::activity_index::put(&mut index, id, row)?;
    }
    index.seal()?;
    let mut state = restart_in(batch, sek, room)?;
    state.next = state.next.max(
        id.checked_add(1)
            .ok_or(Error::MalformedAtRest("private Session id exhausted"))?,
    );
    if saved.row.is_none() {
        state.pending = true;
        state.pending_after = None;
        state.pending_through = state.next;
    }
    state.queue(batch, sek, room)
}

pub(in crate::node::channel) fn remove(
    batch: &mut Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    id: u64,
    saved: &Stored,
) -> Result<()> {
    let mut index = Write::open(batch, sek, room)?;
    super::activity_index::remove(&mut index, id)?;
    index.header.activity_generation =
        index
            .header
            .activity_generation
            .checked_add(1)
            .ok_or(Error::MalformedAtRest(
                "Session activity revision exhausted",
            ))?;
    let (tree, key) = age(saved, id);
    index.set(tree, key, None)?;
    index.set(Tree::PrivateHash, hash_key(&saved.record.hash()), None)?;
    index.set(Tree::PrivateArrival, arrival_key(id), None)?;
    index.set(Tree::PrivateUnread, arrival_key(id), None)?;
    index.set(Tree::Files, arrival_key(id), None)?;
    if let Some(row) = saved
        .row
        .as_ref()
        .filter(|r| crate::node::sessions::is_record(&r.body))
    {
        let key = refresh_key(&row.author, row.created_millis, &row.body);
        if index.find(Tree::RefreshRecords, &key)? == Some(id) {
            index.set(Tree::RefreshRecords, key, None)?;
        }
    }
    if let Some(source) = candidate(saved, id) {
        index.header.private_generation =
            index
                .header
                .private_generation
                .checked_add(1)
                .ok_or(Error::MalformedAtRest(
                    "Session candidate revision exhausted",
                ))?;
        let key = source.position.key();
        if let Some(old) = index.find(Tree::Candidates, &key)? {
            index.set(Tree::Candidates, key, None)?;
            index.delete_descriptor(old)?;
        }
    }
    index.seal()
}

/// Arrival locators are sealed index data; callers bound body reads separately.
pub(in crate::node::channel) fn arrival_before(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    before: Option<u64>,
) -> Result<Option<u64>> {
    let Some(read) = Read::existing(snapshot, sek, room)? else {
        return Ok(None);
    };
    read.previous(Tree::PrivateArrival, before.map(arrival_key))
        .map(|p| p.map(|(_, id)| id))
}

/// Current lifecycle sources only. Activity rows never enter this selector. The descriptor
/// hash pins every multipart continuation to the same opening, end and field sources.
pub(in crate::node::channel) fn lifecycle_sources(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    author: &Digest32,
    session: &str,
    cursor: Option<&crate::node::sessionstream::LifecycleCursor>,
    limit: usize,
) -> Result<(
    Vec<crate::node::sessionstream::Locator>,
    Option<crate::node::sessionstream::LifecycleCursor>,
)> {
    use crate::node::sessionstream::{LifecycleCursor, Locator};
    let read = Read::existing(snapshot, sek, room)?
        .ok_or(Error::StreamRefused("private lifecycle unavailable"))?;
    if !read.header.ready
        || read
            .header
            .published
            .is_none_or(|(_, p)| p != read.header.private_generation)
    {
        return Err(Error::StreamRefused("private lifecycle is refreshing"));
    }
    let group =
        crate::hash::sha256_concat(&[b"vox/session-projection/id/v1", author, session.as_bytes()]);
    let id = read
        .find(Tree::Groups, &hash_key(&group))?
        .ok_or(Error::StreamRefused("private lifecycle unavailable"))?;
    let bytes = read.descriptor(id)?;
    let version = crate::hash::sha256(&bytes);
    let mut d = Decoder::new(&bytes);
    let row = Descriptor::read(&mut d)?;
    d.finish()?;
    if row.node != *author || row.id != session {
        return Err(Error::MalformedAtRest(
            "private lifecycle descriptor binding",
        ));
    }
    if cursor.is_some_and(|c| c.version != version) {
        return Err(Error::StreamRefused("private lifecycle changed"));
    }
    let mut envelopes: Vec<EnvelopeRef> = Vec::with_capacity(5);
    for source in [Some(row.opening), row.ended].into_iter().flatten() {
        let envelope_id =
            read.find(Tree::Envelopes, &source.position.key())?
                .ok_or(Error::StreamRefused(
                    "private lifecycle envelope unavailable",
                ))?;
        let bytes = read.descriptor(envelope_id)?;
        let mut d = Decoder::new(&bytes);
        let envelope = EnvelopeRef::read(&mut d)?;
        d.finish()?;
        if envelope.first != source {
            return Err(Error::MalformedAtRest("private lifecycle source binding"));
        }
        envelopes.push(envelope);
    }
    for field in [row.name, row.harness, row.cwd].into_iter().flatten() {
        if !envelopes.iter().any(|e| e.first == field.envelope.first) {
            envelopes.push(field.envelope);
        }
    }
    let mut at = cursor.cloned().unwrap_or(LifecycleCursor {
        version,
        slot: 0,
        after: 0,
    });
    if at.slot as usize > envelopes.len() {
        return Err(Error::MalformedBundle("private lifecycle cursor range"));
    }
    let mut sources = Vec::new();
    while (at.slot as usize) < envelopes.len() && sources.len() < limit.min(32) {
        let envelope = envelopes[at.slot as usize];
        let source = if envelope.bundle.is_none() {
            if at.after != 0 {
                return Err(Error::MalformedBundle("private lifecycle source offset"));
            }
            at.slot += 1;
            envelope.first
        } else {
            let key = Part::key(&envelope.first.position.hash, at.after);
            let id = read
                .find(Tree::Parts, &key)?
                .ok_or(Error::StreamRefused("private lifecycle part unavailable"))?;
            let bytes = read.descriptor(id)?;
            let mut d = Decoder::new(&bytes);
            let part = Part::read(&mut d)?;
            d.finish()?;
            if part.offset != at.after
                || part.source.author != *author
                || part.number > envelope.parts
            {
                return Err(Error::MalformedAtRest("private lifecycle part binding"));
            }
            at.after = part
                .offset
                .checked_add(part.bytes)
                .ok_or(Error::MalformedAtRest("private lifecycle offset"))?;
            if at.after > envelope.bytes {
                return Err(Error::MalformedAtRest("private lifecycle part length"));
            }
            if at.after == envelope.bytes {
                at.slot += 1;
                at.after = 0;
            }
            part.source
        };
        if !source.position.private || source.author != *author {
            return Err(Error::StreamRefused(
                "private lifecycle source is not privately retained",
            ));
        }
        sources.push(Locator {
            id: source.id,
            hash: source.position.hash,
        });
    }
    let more = (at.slot as usize) < envelopes.len();
    Ok((sources, more.then_some(at)))
}
