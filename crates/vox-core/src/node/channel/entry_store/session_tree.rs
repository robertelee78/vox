//! Session locator pages reuse the room's sealed page codec and COW mutation.
//! The Session owner commits roots and the shared allocator with its own header/data;
//! this adapter owns neither a store, keys, directory, nor publication lifecycle.

use super::*;

pub(crate) type Key = [u8; 64];

pub(crate) struct Read<'a> {
    source: Source<'a>,
    sek: &'a Sek,
    room: &'a Digest32,
}
impl<'a> Read<'a> {
    pub(crate) fn snapshot(
        snapshot: &'a Snapshot,
        sek: &'a Sek,
        room: &'a Digest32,
        kind: SegmentKind,
    ) -> Self {
        Self {
            source: Source::OtherSnapshot(snapshot, kind),
            sek,
            room,
        }
    }
    pub(crate) fn batch(
        batch: &'a Batch<'a>,
        sek: &'a Sek,
        room: &'a Digest32,
        kind: SegmentKind,
    ) -> Self {
        Self {
            source: Source::OtherBatch(batch, kind),
            sek,
            room,
        }
    }
    pub(crate) fn find(&self, root: u64, key: &Key) -> Result<Option<u64>> {
        self.source.number(self.sek, self.room, root, key)
    }
    pub(crate) fn first_after(&self, root: u64, after: Option<Key>) -> Result<Option<(Key, u64)>> {
        let key = match after {
            None => [0; 64],
            Some(key) => match dag_facts::successor(key) {
                Some(key) => key,
                None => return Ok(None),
            },
        };
        self.source
            .first(self.sek, self.room, root, &key, 0)?
            .map(number)
            .transpose()
    }
    pub(crate) fn last_before(&self, root: u64, before: Option<Key>) -> Result<Option<(Key, u64)>> {
        let key = match before {
            None => [u8::MAX; 64],
            Some(key) => match dag_facts::predecessor(key) {
                Some(key) => key,
                None => return Ok(None),
            },
        };
        self.source
            .last(self.sek, self.room, root, &key, 0)?
            .map(number)
            .transpose()
    }
}
fn number((key, value): (Key, Value)) -> Result<(Key, u64)> {
    match value {
        Value::Number(id) => Ok((key, id)),
        _ => Err(invalid("session locator value")),
    }
}

pub(crate) struct Write<'a, 's> {
    inner: super::Write<'a, 's>,
}
impl<'a, 's> Write<'a, 's> {
    pub(crate) fn new(
        batch: &'a mut Batch<'s>,
        sek: &'a Sek,
        room: &'a Digest32,
        kind: SegmentKind,
        next_page: u64,
    ) -> Result<Self> {
        if next_page == 0 {
            return Err(invalid("session allocator is zero"));
        }
        Ok(Self {
            inner: super::Write {
                kind,
                batch,
                sek,
                channel: room,
                directory: Directory {
                    next_page,
                    phase: Phase::Idle,
                    ..Directory::default()
                },
                destination: None,
            },
        })
    }
    pub(crate) fn set(&mut self, root: u64, key: Key, value: Option<u64>) -> Result<u64> {
        self.inner.change_value(root, key, value.map(Value::Number))
    }
    pub(crate) fn next_page(&self) -> u64 {
        self.inner.directory.next_page
    }
}
