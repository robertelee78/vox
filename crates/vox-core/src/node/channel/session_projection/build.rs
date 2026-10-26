//! A bounded, unpublished fold of the room's Session inputs. Each call commits at most one
//! ordinary page of work. Root publication is one atomic header change; an interrupted fold
//! is never confused with an empty set of Sessions.

use sha2::{Digest, Sha256};
use vox_agentcomms::envelope::{Envelope, SESSION, SESSION_END};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256_concat, Digest32};
use crate::node::store::Store;

use super::super::ChannelState;
use super::metadata;
use super::record::{Descriptor, EnvelopeRef, Field, Key, Part, Position, Source};
use super::source::EnvelopeInput;
use super::storage::{Building, Read, Tree, Write};
use super::text::{Input, StringRef};

const WORK_ROWS: usize = 32;
fn invalid(why: &'static str) -> Error {
    Error::MalformedAtRest(why)
}

fn hash_key(hash: &Digest32) -> Key {
    let mut key = [0; 64];
    key[..32].copy_from_slice(hash);
    key
}

fn source(bytes: &[u8]) -> Result<Source> {
    let mut d = Decoder::new(bytes);
    let source = Source::read(&mut d)?;
    d.finish()?;
    Ok(source)
}

fn put_source(index: &mut Write<'_, '_>, source: Source, body: &str) -> Result<()> {
    let logical = crate::node::sessions::is_record(body).then(|| {
        hash_key(&sha256_concat(&[
            b"vox/session-record/v1",
            &source.author,
            &source.position.created.to_be_bytes(),
            body.as_bytes(),
        ]))
    });
    if let Some(key) = logical {
        if let Some(old_id) = index.find(Tree::LogicalRecords, &key)? {
            let old = self::source(&index.descriptor(old_id)?)?;
            // Refresh dedup precedes chronological folding: private insertion order follows
            // every public row, matching the old fold's stable source ordering.
            if (old.position.private, old.position.order, old.position.hash)
                >= (
                    source.position.private,
                    source.position.order,
                    source.position.hash,
                )
            {
                return Ok(());
            }
            index.set(Tree::Gathered, old.position.key(), None)?;
            index.delete_descriptor(old_id)?;
        }
    }
    let mut e = Encoder::new();
    source.put(&mut e);
    let id = index.put_descriptor(&e.finish())?;
    index.set(Tree::Gathered, source.position.key(), Some(id))?;
    if let Some(key) = logical {
        index.set(Tree::LogicalRecords, key, Some(id))?;
    }
    Ok(())
}

/// One fixed-size assembly cursor per active bundle, kept in the sealed tree rather than
/// in a map resident with the room. Old/reordered parts retire this cursor, not any authority.
struct Bundle {
    first: Source,
    next: u64,
    bytes: u64,
}
impl Bundle {
    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 3 {
            return Err(invalid("Session bundle state"));
        }
        let bundle = Self {
            first: Source::read(&mut d)?,
            next: d.uint()?,
            bytes: d.uint()?,
        };
        d.finish()?;
        if bundle.next == 0 {
            return Err(invalid("Session bundle next part"));
        }
        Ok(bundle)
    }
    fn bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3);
        self.first.put(&mut e);
        e.uint(self.next).uint(self.bytes);
        e.finish()
    }
}

fn put_envelope(index: &mut Write<'_, '_>, envelope: EnvelopeRef) -> Result<()> {
    let mut e = Encoder::new();
    envelope.put(&mut e);
    let id = index.put_descriptor(&e.finish())?;
    index.set(Tree::Envelopes, envelope.first.position.key(), Some(id))
}

fn assemble(index: &mut Write<'_, '_>, source: Source, body: &str) -> Result<()> {
    let Ok(env) = Envelope::parse(body) else {
        return Ok(());
    };
    if !matches!(env.kind.as_str(), SESSION | SESSION_END) {
        return put_envelope(
            index,
            EnvelopeRef {
                first: source,
                bundle: None,
                parts: 1,
                bytes: body.len() as u64,
            },
        );
    }
    let Some(tag) = env.data["session_parts"].as_str() else {
        return put_envelope(
            index,
            EnvelopeRef {
                first: source,
                bundle: None,
                parts: 1,
                bytes: body.len() as u64,
            },
        );
    };
    let Ok(tag_hash) = crate::node::link::b32_decode(tag, "Session metadata bundle") else {
        return Ok(());
    };
    if crate::node::link::b32_encode(&tag_hash) != tag {
        return Ok(());
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Ok(());
    };
    let Some(part) = value["part"].as_array() else {
        return Ok(());
    };
    let (Some(number), Some(count)) = (
        part.first().and_then(serde_json::Value::as_u64),
        part.get(1).and_then(serde_json::Value::as_u64),
    ) else {
        return Ok(());
    };
    if number == 0 || count == 0 || number > count {
        return Ok(());
    }
    let mut key = [0; 64];
    key[..32].copy_from_slice(&source.author);
    key[32..].copy_from_slice(&tag_hash);
    if number == 1 {
        if let Some(old) = index.find(Tree::Bundles, &key)? {
            index.delete_descriptor(old)?;
        }
        let start = Bundle {
            first: source,
            next: 1,
            bytes: 0,
        };
        let id = index.put_descriptor(&start.bytes())?;
        index.set(Tree::Bundles, key, Some(id))?;
    }
    let Some(id) = index.find(Tree::Bundles, &key)? else {
        return Ok(());
    };
    let mut bundle = Bundle::read(&index.descriptor(id)?)?;
    if bundle.next != number {
        index.set(Tree::Bundles, key, None)?;
        index.delete_descriptor(id)?;
        return Ok(());
    }
    let length = env.body.len() as u64;
    if length != 0 {
        let part = Part {
            source,
            offset: bundle.bytes,
            bytes: length,
            number,
        };
        let mut e = Encoder::new();
        part.put(&mut e);
        let part_id = index.put_descriptor(&e.finish())?;
        index.set(
            Tree::Parts,
            Part::key(&bundle.first.position.hash, bundle.bytes),
            Some(part_id),
        )?;
    }
    bundle.bytes = bundle
        .bytes
        .checked_add(length)
        .ok_or_else(|| invalid("Session bundle length exhausted"))?;
    if number == count {
        index.set(Tree::Bundles, key, None)?;
        index.delete_descriptor(id)?;
        if bundle.bytes != 0 {
            put_envelope(
                index,
                EnvelopeRef {
                    first: bundle.first,
                    bundle: Some(tag_hash),
                    parts: number,
                    bytes: bundle.bytes,
                },
            )?;
        }
    } else {
        bundle.next = number
            .checked_add(1)
            .ok_or_else(|| invalid("Session part number exhausted"))?;
        index.replace_descriptor(id, &bundle.bytes())?;
    }
    Ok(())
}

struct Event {
    source: Source,
    kind: u8,
    id: String,
    name: Option<Field>,
    harness: Option<Field>,
    cwd: Option<Field>,
}
impl Event {
    fn bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6);
        self.source.put(&mut e);
        e.uint(u64::from(self.kind)).text(&self.id);
        for field in [self.name, self.harness, self.cwd] {
            e.array(usize::from(field.is_some()));
            if let Some(field) = field {
                field.put(&mut e);
            }
        }
        e.finish()
    }
    fn read(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let fields = d.array()?;
        if !matches!(fields, 5 | 6) {
            return Err(invalid("Session event arity"));
        }
        let source = Source::read(&mut d)?;
        let kind = u8::try_from(d.uint()?).map_err(|_| invalid("Session event kind"))?;
        if kind > 2 {
            return Err(invalid("Session event kind"));
        }
        let id = d.text()?;
        if !vox_agentcomms::envelope::is_valid_name(id, vox_agentcomms::envelope::MAX_NAME) {
            return Err(invalid("Session event id"));
        }
        let id = id.to_owned();
        let mut field = || -> Result<Option<Field>> {
            match d.array()? {
                0 => Ok(None),
                1 => Field::read(&mut d).map(Some),
                _ => Err(invalid("Session event field")),
            }
        };
        let name = field()?;
        let harness = field()?;
        let cwd = if fields == 6 { field()? } else { None };
        d.finish()?;
        Ok(Self {
            source,
            kind,
            id,
            name,
            harness,
            cwd,
        })
    }
}

fn interpret(read: &Read<'_>, envelope: EnvelopeRef) -> Result<Option<Event>> {
    let mut input = EnvelopeInput::new(read, envelope);
    let result = (|| {
        if let Some(expected) = envelope.bundle {
            let mut hash = Sha256::new();
            let mut offset = 0;
            let mut buffer = [0; 8192];
            while offset < input.len() {
                let n = input.read_at(offset, &mut buffer)?;
                if n == 0 {
                    return Err(invalid("Session complete bundle ended early"));
                }
                offset = offset
                    .checked_add(n as u64)
                    .ok_or_else(|| invalid("Session bundle offset exhausted"))?;
                hash.update(&buffer[..n]);
            }
            let actual: Digest32 = hash.finalize().into();
            if actual != expected {
                return Ok(None);
            }
        }
        let Some(meta) = metadata::parse(&mut input)? else {
            return Ok(None);
        };
        if meta.from.trim().is_empty() || (envelope.bundle.is_some() && meta.kind != SESSION) {
            return Ok(None);
        }
        let kind = match meta.kind.as_str() {
            SESSION => 1,
            SESSION_END => 2,
            _ => 0,
        };
        if kind == 0 && meta.name.is_none() {
            return Ok(None);
        }
        let field = |text: StringRef| Field {
            envelope,
            start: text.start,
            end: text.end,
            bytes: text.bytes,
            hash: text.hash,
        };
        Ok(Some(Event {
            source: envelope.first,
            kind,
            id: meta.from,
            name: meta.name.map(field),
            harness: meta.harness.map(field),
            cwd: (kind == 1).then_some(meta.cwd).flatten().map(field),
        }))
    })();
    if input.retired() {
        Ok(None)
    } else {
        result
    }
}

fn fold(index: &mut Write<'_, '_>, event: Event) -> Result<()> {
    let group = hash_key(&sha256_concat(&[
        b"vox/session-projection/id/v1",
        &event.source.author,
        event.id.as_bytes(),
    ]));
    let prior = index.find(Tree::Groups, &group)?;
    let mut row = if let Some(id) = prior {
        let bytes = index.descriptor(id)?;
        let mut d = Decoder::new(&bytes);
        let row = Descriptor::read(&mut d)?;
        d.finish()?;
        if row.node != event.source.author || row.id != event.id {
            return Err(invalid("Session group binding"));
        }
        Some(row)
    } else {
        None
    };
    let old_opening = row.as_ref().map(|row| row.opening.position.hash);
    let was_open = row.as_ref().is_some_and(|row| row.ended.is_none());
    let mut new = false;
    match (event.kind, row.as_mut()) {
        (1, Some(row)) if row.ended.is_none() => {
            if row.opening.position.created == event.source.position.created {
                row.opening = event.source;
            }
            if event.cwd.is_some() {
                row.cwd = event.cwd;
            }
            if event.name.is_some() {
                row.name = event.name;
                row.named_at = event.source.position;
            }
        }
        (1, _) => {
            new = true;
            row = Some(Descriptor {
                node: event.source.author,
                id: event.id,
                opening: event.source,
                position: event.source.position,
                name: event.name,
                harness: event.harness,
                cwd: event.cwd,
                named_at: event.source.position,
                ended: None,
            });
        }
        (2, Some(row)) if row.ended.is_none() => {
            row.ended = Some(event.source);
        }
        (2, Some(row))
            if row
                .ended
                .is_some_and(|end| end.position.created == event.source.position.created) =>
        {
            row.ended = Some(event.source);
        }
        (0, Some(row)) if row.ended.is_none() && event.source.position > row.named_at => {
            row.name = event.name;
            row.named_at = event.source.position;
        }
        _ => return Ok(()),
    }
    let Some(row) = row else {
        return Ok(());
    };
    let mut e = Encoder::new();
    row.put(&mut e);
    let bytes = e.finish();
    let id = if !new {
        let id = prior.ok_or_else(|| invalid("Session update missing its row"))?;
        index.replace_descriptor(id, &bytes)?;
        id
    } else {
        index.put_descriptor(&bytes)?
    };
    if !new {
        if let Some(old) = old_opening.filter(|old| *old != row.opening.position.hash) {
            index.set(Tree::OpeningHash, hash_key(&old), None)?;
        }
    } else {
        let key = hash_key(&row.node);
        let count = index
            .find(Tree::Counts, &key)?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| invalid("Session opening count exhausted"))?;
        index.set(Tree::Counts, key, Some(count))?;
    }
    let is_open = row.ended.is_none();
    if new || was_open != is_open {
        let key = hash_key(&row.node);
        let old = index.find(Tree::OpenCounts, &key)?.unwrap_or(0);
        let count = if is_open {
            old.checked_add(1)
        } else {
            old.checked_sub(1)
        }
        .ok_or_else(|| invalid("Session open count invalid"))?;
        index.set(Tree::OpenCounts, key, Some(count))?;
    }
    index.set(
        Tree::OpeningHash,
        hash_key(&row.opening.position.hash),
        Some(id),
    )?;
    index.set(Tree::Groups, group, Some(id))?;
    let mut key = [0; 64];
    key[..8].copy_from_slice(&id.to_be_bytes());
    index.set(Tree::Openings, key, Some(id))?;
    let mut key = [0; 64];
    key[..32].copy_from_slice(&row.node);
    key[32..40].copy_from_slice(&id.to_be_bytes());
    index.set(Tree::AuthorOpenings, key, Some(id))?;
    index.set(Tree::OpenSessions, key, is_open.then_some(id))?;
    index.set(
        Tree::Lifecycle,
        super::query::lifecycle_key(&row.node, row.position.created, id, false),
        Some(id),
    )?;
    if let Some(end) = row.ended {
        index.set(
            Tree::Lifecycle,
            super::query::lifecycle_key(&row.node, end.position.created, id, true),
            Some(id),
        )?;
    }
    Ok(())
}

fn advance_phase(index: &mut Write<'_, '_>, phase: u8) -> Result<()> {
    let work = index
        .header
        .building
        .as_mut()
        .ok_or_else(|| invalid("Session work state absent"))?;
    work.phase = phase;
    work.cursor = None;
    Ok(())
}

/// One ordinary page of work. The caller drives this from actor maintenance, not a client
/// wait loop. A reader sees the old valid generation or an explicit refreshing refusal.
pub(super) fn advance(ch: &ChannelState, store: &Store, now: u64) -> Result<bool> {
    let view = ch.entries.render_view(store, &ch.sek, &ch.channel_id)?;
    let public = view.session_revision();
    let snapshot = view.snapshot();
    let captured = Read::existing(snapshot, &ch.sek, &ch.channel_id)?
        .map(|read| read.with_sources(ch, &view, now));
    let header = captured
        .as_ref()
        .map(|read| read.header.clone())
        .unwrap_or_default();
    let mut batch = store.batch()?;
    let mut index = Write::open(&mut batch, &ch.sek, &ch.channel_id)?;
    let current = (public, header.private_generation);
    if let Some(work) = &mut index.header.building {
        if work.phase != 7 && (work.public, work.private) != current {
            work.phase = 7;
            work.cursor = None;
            work.cleanup = 0;
        }
    } else if index.header.published != Some(current) {
        index.header.building = Some(Building::new(current.0, current.1));
    } else {
        return Ok(false);
    }
    let state = index
        .header
        .building
        .clone()
        .ok_or_else(|| invalid("Session build absent"))?;
    let mut index = index.work()?;
    let mut cursor = state.cursor;
    match state.phase {
        1 => {
            for _ in 0..WORK_ROWS {
                let after = cursor
                    .map(|key| Position::from_key(&key).map(|p| (p.created, p.order, p.hash)))
                    .transpose()?;
                let Some(((created, clock, hash), fact)) = view.session_candidate(after)? else {
                    advance_phase(&mut index, 2)?;
                    break;
                };
                let position = Position {
                    created,
                    private: false,
                    order: clock,
                    hash,
                };
                let row = view
                    .row(&hash)?
                    .ok_or_else(|| invalid("Session public candidate missing"))?;
                let source = Source {
                    position,
                    author: row.author,
                    id: fact.cache,
                };
                if let Some(read) = &captured {
                    if !read.retained(source)? {
                        cursor = Some(position.key());
                        continue;
                    }
                }
                put_source(&mut index, source, &row.text)?;
                cursor = Some(position.key());
            }
        }
        2 => {
            if let Some(read) = &captured {
                for _ in 0..WORK_ROWS {
                    let Some((key, id)) = read.next(Tree::Candidates, cursor)? else {
                        advance_phase(&mut index, 3)?;
                        break;
                    };
                    let source = source(&read.descriptor(id)?)?;
                    if let Some(body) = read.source(source)? {
                        put_source(&mut index, source, &body)?;
                    }
                    cursor = Some(key);
                }
            } else {
                advance_phase(&mut index, 3)?;
            }
        }
        3 => {
            let read = Read::open(snapshot, &ch.sek, &ch.channel_id)?
                .with_sources(ch, &view, now)
                .work()?;
            for _ in 0..WORK_ROWS {
                let Some((key, id)) = read.next(Tree::Gathered, cursor)? else {
                    advance_phase(&mut index, 4)?;
                    break;
                };
                let source = source(&read.descriptor(id)?)?;
                if let Some(body) = read.source(source)? {
                    assemble(&mut index, source, &body)?;
                }
                cursor = Some(key);
            }
        }
        4 => {
            let read = Read::open(snapshot, &ch.sek, &ch.channel_id)?
                .with_sources(ch, &view, now)
                .work()?;
            // At most one metadata envelope is interpreted per turn. Its fields stream from
            // individual records; no declared part count controls a resident allocation.
            if let Some((key, id)) = read.next(Tree::Envelopes, cursor)? {
                let bytes = read.descriptor(id)?;
                let mut d = Decoder::new(&bytes);
                let envelope = EnvelopeRef::read(&mut d)?;
                d.finish()?;
                if let Some(event) = interpret(&read, envelope)? {
                    let id = index.put_descriptor(&event.bytes())?;
                    index.set(Tree::Events, key, Some(id))?;
                }
                cursor = Some(key);
            } else {
                advance_phase(&mut index, 5)?;
            }
        }
        5 => {
            for _ in 0..WORK_ROWS {
                let Some((key, id)) = index.next(Tree::Events, cursor)? else {
                    advance_phase(&mut index, 6)?;
                    break;
                };
                let event = Event::read(&index.descriptor(id)?)?;
                let retained = match &captured {
                    Some(read) => read.retained(event.source)?,
                    None => true,
                };
                if retained {
                    fold(&mut index, event)?;
                }
                cursor = Some(key);
            }
        }
        6 => index.publish()?,
        7 => {
            index.cleanup(WORK_ROWS)?;
        }
        _ => return Err(invalid("Session build phase")),
    }
    if let Some(work) = &mut index.header.building {
        if work.phase == state.phase && state.phase != 7 {
            work.cursor = cursor;
        }
    }
    index.seal()?;
    batch.commit()?;
    Ok(true)
}
