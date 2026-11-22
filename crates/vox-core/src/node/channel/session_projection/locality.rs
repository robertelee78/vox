//! Derived source membership for one metadata fold. Signed records are never rewritten.
//! A unit is one Session, or one multipart dependency until its inner Session is known.
//! Temporary folds own their pages; only publication mutates the shared published paths.

use super::record::{Descriptor, Key, Position, Source};
use crate::atrest::sek::Sek;
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256_concat, Digest32};
use crate::node::store::Batch;
use vox_agentcomms::envelope::{Envelope, SESSION, SESSION_END};

pub(in crate::node::channel) fn observe_public(
    batch: &mut Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    row: &super::super::Rendered,
    clock: u64,
    add: bool,
) -> Result<()> {
    observe(
        batch,
        sek,
        room,
        Source {
            position: Position {
                created: row.created_millis,
                private: false,
                order: clock,
                hash: row.entry_hash,
            },
            author: row.author,
            id: row.arrival,
        },
        &row.text,
        add,
    )
}
use super::storage::{Tree, Write};

fn bad() -> Error {
    Error::MalformedAtRest("Session metadata membership")
}
fn hash_key(hash: &Digest32) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(hash);
    key
}
pub(super) fn group(author: &Digest32, id: &str) -> Key {
    hash_key(&sha256_concat(&[
        b"vox/session-projection/id/v1",
        author,
        id.as_bytes(),
    ]))
}
pub(in crate::node::channel) fn candidate(body: &str) -> bool {
    Envelope::parse(body).is_ok_and(|envelope| candidate_envelope(&envelope))
}

pub(in crate::node::channel) fn candidate_envelope(envelope: &Envelope) -> bool {
    matches!(envelope.kind.as_str(), SESSION | SESSION_END)
        || (!envelope.from.trim().is_empty() && envelope.at.session_name.is_some())
}

fn unit(source: Source, body: &str) -> Option<Key> {
    let envelope = Envelope::parse(body).ok()?;
    if matches!(envelope.kind.as_str(), SESSION | SESSION_END) {
        if let Some(tag) = envelope.data["session_parts"].as_str() {
            let tag_hash = crate::node::link::b32_decode(tag, "Session metadata bundle").ok()?;
            if crate::node::link::b32_encode(&tag_hash) != tag {
                return None;
            }
            let mut key = hash_key(&sha256_concat(&[
                b"vox/session-projection/bundle/v1",
                &source.author,
                &tag_hash,
            ]));
            key[63] = 1;
            return Some(key);
        }
    }
    if envelope.from.trim().is_empty() {
        return None;
    }
    Some(group(&source.author, &envelope.from))
}

#[derive(Default)]
struct Unit {
    sources: u64,
    events: u64,
    parts: u64,
}
impl Unit {
    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 4 || d.uint()? != 1 {
            return Err(bad());
        }
        let value = Self {
            sources: d.uint()?,
            events: d.uint()?,
            parts: d.uint()?,
        };
        d.finish()?;
        Ok(value)
    }
    fn bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(1)
            .uint(self.sources)
            .uint(self.events)
            .uint(self.parts);
        e.finish()
    }
}
fn load(index: &Write<'_, '_>, key: &Key, canonical: bool) -> Result<Option<(u64, Unit)>> {
    let id = if canonical {
        index.canonical_find(Tree::MetadataUnits, key)?
    } else {
        index.find(Tree::MetadataUnits, key)?
    };
    id.map(|id| Unit::read(&index.descriptor(id)?).map(|unit| (id, unit)))
        .transpose()
}
fn store(
    index: &mut Write<'_, '_>,
    key: Key,
    old: Option<u64>,
    value: &Unit,
    canonical: bool,
) -> Result<()> {
    let id = if let Some(id) = old {
        index.replace_descriptor(id, &value.bytes())?;
        id
    } else {
        index.put_descriptor(&value.bytes())?
    };
    if canonical {
        index.canonical_set(Tree::MetadataUnits, key, Some(id))
    } else {
        index.set(Tree::MetadataUnits, key, Some(id))
    }
}

/// Before lazy backfill publishes, the original bounded room fold captures these inputs.
fn observe(
    batch: &mut Batch<'_>,
    sek: &Sek,
    room: &Digest32,
    source: Source,
    body: &str,
    add: bool,
) -> Result<()> {
    let mut index = Write::open(batch, sek, room)?;
    if !index.header.locality {
        return Ok(());
    }
    source_change(&mut index, source, body, add, true)?;
    index.seal()
}
pub(super) fn source_saved(
    index: &mut Write<'_, '_>,
    source: Source,
    body: &str,
    add: bool,
) -> Result<()> {
    if index.header.locality {
        source_change(index, source, body, add, true)?;
    }
    Ok(())
}
fn source_change(
    index: &mut Write<'_, '_>,
    source: Source,
    body: &str,
    add: bool,
    canonical: bool,
) -> Result<()> {
    let Some(key) = unit(source, body) else {
        return Ok(());
    };
    let old = load(index, &key, canonical)?;
    let mut value = old
        .as_ref()
        .map(|(_, u)| Unit {
            sources: u.sources,
            events: u.events,
            parts: u.parts,
        })
        .unwrap_or_default();
    let position = source.position.key();
    let prior = index.waiting_find(value.sources, &position)?;
    if add {
        if let Some(id) = prior {
            let bytes = index.descriptor(id)?;
            let mut d = Decoder::new(&bytes);
            let previous = Source::read(&mut d)?;
            d.finish()?;
            if previous == source {
                return Ok(());
            }
        }
    }
    if !add && prior.is_none() {
        return Ok(());
    }
    if let Some(id) = prior {
        index.delete_descriptor(id)?;
    }
    let id = if add {
        let mut e = Encoder::new();
        source.put(&mut e);
        Some(index.put_descriptor(&e.finish())?)
    } else {
        None
    };
    value.sources = index.waiting_set(value.sources, position, id)?;
    store(index, key, old.map(|(id, _)| id), &value, canonical)?;
    if canonical {
        index.canonical_set(Tree::MetadataDirty, key, Some(1))?;
    }
    Ok(())
}

pub(super) fn backfill_source(index: &mut Write<'_, '_>, source: Source, body: &str) -> Result<()> {
    if index
        .header
        .building
        .as_ref()
        .is_some_and(|work| work.target.is_none())
    {
        source_change(index, source, body, true, false)?;
    }
    Ok(())
}
pub(super) fn backfill_part(
    index: &mut Write<'_, '_>,
    source: Source,
    body: &str,
    key: Key,
    id: u64,
) -> Result<()> {
    if index
        .header
        .building
        .as_ref()
        .is_none_or(|work| work.target.is_some())
    {
        return Ok(());
    }
    let Some(unit_key) = unit(source, body) else {
        return Ok(());
    };
    let (unit_id, mut value) = load(index, &unit_key, false)?.ok_or_else(bad)?;
    value.parts = index.waiting_set(value.parts, key, Some(id))?;
    store(index, unit_key, Some(unit_id), &value, false)
}
pub(super) fn backfill_event(
    index: &mut Write<'_, '_>,
    source: Source,
    body: &str,
    event: &super::build::Event,
) -> Result<()> {
    if index
        .header
        .building
        .as_ref()
        .is_none_or(|work| work.target.is_some())
    {
        return Ok(());
    }
    let Some(unit_key) = unit(source, body) else {
        return Ok(());
    };
    let (unit_id, mut value) = load(index, &unit_key, false)?.ok_or_else(bad)?;
    let key = event.source.position.key();
    let id = index.put_descriptor(&event.bytes())?;
    if let Some(old) = index.waiting_find(value.events, &key)? {
        index.delete_descriptor(old)?;
    }
    value.events = index.waiting_set(value.events, key, Some(id))?;
    let group = group(&event.source.author, &event.id);
    let root = index.find(Tree::MetadataEvents, &group)?.unwrap_or(0);
    let root = index.waiting_set(root, key, Some(id))?;
    index.set(Tree::MetadataEvents, group, Some(root))?;
    store(index, unit_key, Some(unit_id), &value, false)
}
pub(super) fn chronological(
    index: &mut Write<'_, '_>,
    row: &Descriptor,
    id: u64,
    add: bool,
    canonical: bool,
) -> Result<()> {
    for (tree, present) in [
        (Tree::ChronOpenings, add),
        (Tree::ChronOpenSessions, add && row.ended.is_none()),
    ] {
        let key = hash_key(&row.node);
        let root = if canonical {
            index.canonical_find(tree, &key)?
        } else {
            index.find(tree, &key)?
        }
        .unwrap_or(0);
        let root = index.waiting_set(root, row.position.key(), present.then_some(id))?;
        if canonical {
            index.canonical_set(tree, key, (root != 0).then_some(root))?;
        } else {
            index.set(tree, key, (root != 0).then_some(root))?;
        }
    }
    Ok(())
}
pub(super) fn backfill_opening(index: &mut Write<'_, '_>, row: &Descriptor, id: u64) -> Result<()> {
    if index
        .header
        .building
        .as_ref()
        .is_some_and(|work| work.target.is_some())
    {
        return Ok(());
    }
    let key = group(&row.node, &row.id);
    let root = index.find(Tree::MetadataOpenings, &key)?.unwrap_or(0);
    let root = index.waiting_set(root, row.position.key(), Some(id))?;
    index.set(Tree::MetadataOpenings, key, Some(root))
}
pub(super) fn next_source(
    index: &Write<'_, '_>,
    target: &Key,
    after: Option<Key>,
) -> Result<Option<(Key, Source)>> {
    let (_, unit) = load(index, target, true)?.ok_or_else(bad)?;
    index
        .nested_next(unit.sources, after)?
        .map(|(key, id)| {
            let bytes = index.descriptor(id)?;
            let mut d = Decoder::new(&bytes);
            let source = Source::read(&mut d)?;
            d.finish()?;
            Ok((key, source))
        })
        .transpose()
}

fn descriptor(index: &Write<'_, '_>, id: u64) -> Result<Descriptor> {
    let bytes = index.descriptor(id)?;
    let mut d = Decoder::new(&bytes);
    let row = Descriptor::read(&mut d)?;
    d.finish()?;
    Ok(row)
}
fn author_key(author: &Digest32, id: u64) -> Key {
    let mut key = hash_key(author);
    key[32..40].copy_from_slice(&id.to_be_bytes());
    key
}
fn opening_key(id: u64) -> Key {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&id.to_be_bytes());
    key
}
fn adjust(index: &mut Write<'_, '_>, tree: Tree, key: Key, add: bool) -> Result<()> {
    let old = index.canonical_find(tree, &key)?.unwrap_or(0);
    let next = if add {
        old.checked_add(1)
    } else {
        old.checked_sub(1)
    }
    .ok_or_else(bad)?;
    index.canonical_set(tree, key, (next != 0).then_some(next))
}
fn paths(index: &mut Write<'_, '_>, row: &Descriptor, id: u64, add: bool) -> Result<()> {
    chronological(index, row, id, add, true)?;
    let value = add.then_some(id);
    index.canonical_set(Tree::Openings, opening_key(id), value)?;
    index.canonical_set(Tree::AuthorOpenings, author_key(&row.node, id), value)?;
    index.canonical_set(
        Tree::OpenSessions,
        author_key(&row.node, id),
        (add && row.ended.is_none()).then_some(id),
    )?;
    index.canonical_set(
        Tree::OpeningHash,
        hash_key(&row.opening.position.hash),
        value,
    )?;
    index.canonical_set(
        Tree::Lifecycle,
        super::query::lifecycle_key(&row.node, row.position.created, id, false),
        value,
    )?;
    if let Some(end) = row.ended {
        index.canonical_set(
            Tree::Lifecycle,
            super::query::lifecycle_key(&row.node, end.position.created, id, true),
            value,
        )?;
    }
    adjust(index, Tree::Counts, hash_key(&row.node), add)?;
    if row.ended.is_none() {
        adjust(index, Tree::OpenCounts, hash_key(&row.node), add)?;
    }
    let digest = sha256_concat(&[
        b"vox/session-opening-set/v1",
        &row.node,
        &row.opening.position.hash,
    ]);
    for lane in 0..4 {
        let offset = lane as usize * 8;
        let amount = u64::from_be_bytes(std::array::from_fn(|byte| digest[offset + byte]));
        let key = super::storage::opening_lane_key(&row.node, lane);
        let old = index.canonical_find(Tree::Counts, &key)?.unwrap_or(0);
        let next = if add {
            old.wrapping_add(amount)
        } else {
            old.wrapping_sub(amount)
        };
        index.canonical_set(Tree::Counts, key, (next != 0).then_some(next))?;
    }
    Ok(())
}

/// Replay one group's canonical events into isolated fold roots, then replace its paths
/// in this same transaction. Untouched trees are never cloned or handed to cleanup.
fn publish_group(index: &mut Write<'_, '_>, group: Key) -> Result<()> {
    let events = index
        .canonical_find(Tree::MetadataEvents, &group)?
        .unwrap_or(0);
    let mut after = None;
    while let Some((key, id)) = index.nested_next(events, after)? {
        let event = super::build::Event::read(&index.descriptor(id)?)?;
        super::build::fold(index, event)?;
        after = Some(key);
    }
    let old_root = index
        .canonical_find(Tree::MetadataOpenings, &group)?
        .unwrap_or(0);
    let mut after = None;
    while let Some((key, id)) = index.nested_next(old_root, after)? {
        let row = descriptor(index, id)?;
        paths(index, &row, id, false)?;
        after = Some(key);
    }
    let latest = index.find(Tree::Groups, &group)?;
    let mut replacement = 0;
    let mut latest_id = None;
    // Work Openings owns only this group's descriptors. A replacement with the same
    // canonical opening keeps its old id, so unchanged pagination order stays unchanged.
    while let Some((key, id)) = index.next(Tree::Openings, None)? {
        let row = descriptor(index, id)?;
        let reuse = index.waiting_find(old_root, &row.position.key())?;
        let published = if let Some(old) = reuse {
            let bytes = index.descriptor(id)?;
            index.replace_descriptor(old, &bytes)?;
            index.delete_descriptor(id)?;
            old
        } else {
            id
        };
        paths(index, &row, published, true)?;
        replacement = index.waiting_set(replacement, row.position.key(), Some(published))?;
        if latest == Some(id) {
            latest_id = Some(published);
        }
        index.set(Tree::Openings, key, None)?;
    }
    index.canonical_set(Tree::Groups, group, latest_id)?;
    index.canonical_set(
        Tree::MetadataOpenings,
        group,
        (replacement != 0).then_some(replacement),
    )?;
    // Remove old descriptors not reused. Old membership owns only its pages.
    let mut after = None;
    while let Some((key, id)) = index.nested_next(old_root, after)? {
        if index.waiting_find(replacement, &key)?.is_none() {
            index.delete_descriptor(id)?;
        }
        after = Some(key);
    }
    drop_nested(index, old_root, false)?;
    // These work paths reference transferred descriptors and own only their pages.
    for tree in [
        Tree::Groups,
        Tree::OpeningHash,
        Tree::Counts,
        Tree::AuthorOpenings,
        Tree::OpenCounts,
        Tree::OpenSessions,
        Tree::Lifecycle,
        Tree::MetadataOpenings,
    ] {
        while let Some((key, _)) = index.next(tree, None)? {
            index.set(tree, key, None)?;
        }
    }
    Ok(())
}
fn drop_nested(index: &mut Write<'_, '_>, mut root: u64, descriptors: bool) -> Result<()> {
    while let Some((key, id)) = index.nested_next(root, None)? {
        root = index.waiting_set(root, key, None)?;
        if descriptors {
            index.delete_descriptor(id)?;
        }
    }
    Ok(())
}

/// The temporary source/envelope fold completed. Update its old and new group before
/// retiring any prior event locator. A kill before this commit retains the old roots.
pub(super) fn publish(index: &mut Write<'_, '_>, target: Key) -> Result<()> {
    let (unit_id, mut value) = load(index, &target, true)?.ok_or_else(bad)?;
    while let Some((key, id)) = index.nested_next(value.events, None)? {
        let event = super::build::Event::read(&index.descriptor(id)?)?;
        let group = group(&event.source.author, &event.id);
        index.set(Tree::MetadataDirty, group, Some(1))?;
        let root = index
            .canonical_find(Tree::MetadataEvents, &group)?
            .unwrap_or(0);
        let root = index.waiting_set(root, key, None)?;
        index.canonical_set(Tree::MetadataEvents, group, (root != 0).then_some(root))?;
        value.events = index.waiting_set(value.events, key, None)?;
        index.delete_descriptor(id)?;
    }
    while let Some((key, id)) = index.nested_next(value.parts, None)? {
        index.canonical_set(Tree::Parts, key, None)?;
        value.parts = index.waiting_set(value.parts, key, None)?;
        index.delete_descriptor(id)?;
    }
    while let Some((key, id)) = index.next(Tree::Parts, None)? {
        index.canonical_set(Tree::Parts, key, Some(id))?;
        value.parts = index.waiting_set(value.parts, key, Some(id))?;
        index.set(Tree::Parts, key, None)?;
    }
    while let Some((key, id)) = index.next(Tree::Events, None)? {
        let event = super::build::Event::read(&index.descriptor(id)?)?;
        let group = group(&event.source.author, &event.id);
        index.set(Tree::MetadataDirty, group, Some(1))?;
        let root = index
            .canonical_find(Tree::MetadataEvents, &group)?
            .unwrap_or(0);
        let root = index.waiting_set(root, key, Some(id))?;
        index.canonical_set(Tree::MetadataEvents, group, Some(root))?;
        value.events = index.waiting_set(value.events, key, Some(id))?;
        index.set(Tree::Events, key, None)?;
    }
    if value.sources == 0 && value.events == 0 && value.parts == 0 {
        index.canonical_set(Tree::MetadataUnits, target, None)?;
        index.delete_descriptor(unit_id)?;
    } else {
        store(index, target, Some(unit_id), &value, true)?;
    }
    while let Some((group, _)) = index.next(Tree::MetadataDirty, None)? {
        publish_group(index, group)?;
        index.set(Tree::MetadataDirty, group, None)?;
    }
    index.canonical_set(Tree::MetadataDirty, target, None)?;
    let complete = index.canonical_next(Tree::MetadataDirty, None)?.is_none();
    let work = index.header.building.as_mut().ok_or_else(bad)?;
    if complete {
        index.header.published = Some((work.public, work.private));
    }
    index.header.publication = index.header.publication.checked_add(1).ok_or_else(bad)?;
    work.phase = 7;
    work.cursor = None;
    work.cleanup = 0;
    Ok(())
}

/// One cleanup step; nested roots are never mistaken for descriptor ids. Only a unit's
/// source and event trees own descriptors; group membership and part locators do not.
pub(super) fn cleanup(index: &mut Write<'_, '_>, tree: Tree, key: Key, id: u64) -> Result<bool> {
    match tree {
        Tree::MetadataUnits => {
            let mut unit = Unit::read(&index.descriptor(id)?)?;
            for slot in 0..3 {
                let root = match slot {
                    0 => unit.sources,
                    1 => unit.events,
                    _ => unit.parts,
                };
                if let Some((at, value)) = index.nested_next(root, None)? {
                    let root = index.waiting_set(root, at, None)?;
                    match slot {
                        0 => unit.sources = root,
                        1 => unit.events = root,
                        _ => unit.parts = root,
                    }
                    if slot != 2 {
                        index.delete_descriptor(value)?;
                    }
                    index.replace_descriptor(id, &unit.bytes())?;
                    return Ok(true);
                }
            }
            index.set(tree, key, None)?;
            index.delete_descriptor(id)?;
            Ok(true)
        }
        Tree::MetadataEvents
        | Tree::MetadataOpenings
        | Tree::ChronOpenings
        | Tree::ChronOpenSessions => {
            if let Some((at, _)) = index.nested_next(id, None)? {
                let root = index.waiting_set(id, at, None)?;
                index.set(tree, key, (root != 0).then_some(root))?;
            } else {
                index.set(tree, key, None)?;
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}
