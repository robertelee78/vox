//! Compact coordinates for the Session projection. Text stays in authenticated sealed
//! records; a field reference never owns a multipart name or harness string.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;

pub(super) type Key = [u8; 64];

fn invalid(why: &'static str) -> Error {
    Error::MalformedAtRest(why)
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| invalid("Session projection digest"))
}

/// The old fold's stable order: creation time, public room order before private insertion
/// order, and the authenticated entry identity. Private order is its retained storage id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Position {
    pub created: u64,
    pub private: bool,
    pub order: u64,
    pub hash: Digest32,
}

impl Position {
    pub fn key(self) -> Key {
        let mut key = [0; 64];
        key[..8].copy_from_slice(&self.created.to_be_bytes());
        key[8] = u8::from(self.private);
        key[9..17].copy_from_slice(&self.order.to_be_bytes());
        key[17..49].copy_from_slice(&self.hash);
        key
    }

    pub fn from_key(key: &Key) -> Result<Self> {
        if key[8] > 1 || key[49..].iter().any(|b| *b != 0) {
            return Err(invalid("Session projection position"));
        }
        let number = |bytes: &[u8]| -> Result<u64> {
            Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
                invalid("Session projection position number")
            })?))
        };
        Ok(Self {
            created: number(&key[..8])?,
            private: key[8] == 1,
            order: number(&key[9..17])?,
            hash: key[17..49]
                .try_into()
                .map_err(|_| invalid("Session projection position hash"))?,
        })
    }

    fn put(self, e: &mut Encoder) {
        e.bytes(&self.key());
    }

    fn read(d: &mut Decoder<'_>) -> Result<Self> {
        let key: Key = d
            .bytes()?
            .try_into()
            .map_err(|_| invalid("Session projection position size"))?;
        Self::from_key(&key)
    }
}

/// One original row. `id` identifies PlaintextCache or PrivateSession according to
/// `position.private`; the hash and author are checked again whenever its bytes are opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Source {
    pub position: Position,
    pub author: Digest32,
    pub id: u64,
}

impl Source {
    pub fn put(self, e: &mut Encoder) {
        e.array(3);
        self.position.put(e);
        e.bytes(&self.author).uint(self.id);
    }

    pub fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 3 {
            return Err(invalid("Session projection source arity"));
        }
        let source = Self {
            position: Position::read(d)?,
            author: digest(d)?,
            id: d.uint()?,
        };
        if source.id == 0 {
            return Err(invalid("Session projection source id"));
        }
        Ok(source)
    }
}

/// A complete envelope is either one bounded row or an authenticated multipart bundle.
/// Bundle coordinates identify its first part, not the location of its last part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EnvelopeRef {
    pub first: Source,
    pub bundle: Option<Digest32>,
    pub parts: u64,
    pub bytes: u64,
}

impl EnvelopeRef {
    pub fn put(self, e: &mut Encoder) {
        e.array(4);
        self.first.put(e);
        e.bytes(self.bundle.as_ref().map_or(&[][..], |h| &h[..]))
            .uint(self.parts)
            .uint(self.bytes);
    }

    pub fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 4 {
            return Err(invalid("Session projection envelope arity"));
        }
        let first = Source::read(d)?;
        let bundle = match d.bytes()? {
            [] => None,
            bytes => Some(
                bytes
                    .try_into()
                    .map_err(|_| invalid("Session projection bundle digest"))?,
            ),
        };
        let parts = d.uint()?;
        let bytes = d.uint()?;
        if parts == 0 || (bundle.is_none() && parts != 1) || bytes == 0 {
            return Err(invalid("Session projection envelope coordinates"));
        }
        Ok(Self {
            first,
            bundle,
            parts,
            bytes,
        })
    }
}

/// A JSON string's encoded range and exact decoded length/hash. The range includes its
/// quotes. UTF-8 and escapes are validated before this reference is published. Serving
/// rereads the original parts and decodes into the existing bounded IPC byte-page buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Field {
    pub envelope: EnvelopeRef,
    pub start: u64,
    pub end: u64,
    pub bytes: u64,
    pub hash: Digest32,
}

impl Field {
    pub fn put(self, e: &mut Encoder) {
        e.array(5);
        self.envelope.put(e);
        e.uint(self.start)
            .uint(self.end)
            .uint(self.bytes)
            .bytes(&self.hash);
    }

    pub fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 5 {
            return Err(invalid("Session projection field arity"));
        }
        let field = Self {
            envelope: EnvelopeRef::read(d)?,
            start: d.uint()?,
            end: d.uint()?,
            bytes: d.uint()?,
            hash: digest(d)?,
        };
        if field.end > field.envelope.bytes
            || field.start.checked_add(2).is_none_or(|min| min > field.end)
            || field.bytes > field.end - field.start - 2
        {
            return Err(invalid("Session projection field range"));
        }
        Ok(field)
    }
}

/// A Session id already passes the envelope's existing 64-byte rule. Its fields remain
/// references even when a legal multipart name is much larger than an IPC page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Descriptor {
    pub node: Digest32,
    pub id: String,
    pub opening: Source,
    pub position: Position,
    pub name: Option<Field>,
    pub harness: Option<Field>,
    pub named_at: Position,
    pub ended: Option<Source>,
}

impl Descriptor {
    pub fn put(&self, e: &mut Encoder) {
        e.array(9).uint(1).bytes(&self.node).text(&self.id);
        self.opening.put(e);
        self.position.put(e);
        optional_field(e, self.name);
        optional_field(e, self.harness);
        self.named_at.put(e);
        e.array(usize::from(self.ended.is_some()));
        if let Some(ended) = self.ended {
            ended.put(e);
        }
    }

    pub fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 9 || d.uint()? != 1 {
            return Err(invalid("Session projection descriptor version"));
        }
        let node = digest(d)?;
        let text = d.text()?;
        if !vox_agentcomms::envelope::is_valid_name(text, vox_agentcomms::envelope::MAX_NAME) {
            return Err(invalid("Session projection id"));
        }
        let id = text.to_owned();
        let opening = Source::read(d)?;
        let position = Position::read(d)?;
        let name = read_optional_field(d)?;
        let harness = read_optional_field(d)?;
        let named_at = Position::read(d)?;
        let ended = match d.array()? {
            0 => None,
            1 => Some(Source::read(d)?),
            _ => return Err(invalid("Session projection end arity")),
        };
        if opening.author != node
            || ended.is_some_and(|s| s.author != node)
            || name.is_some_and(|f| f.envelope.first.author != node)
            || harness.is_some_and(|f| f.envelope.first.author != node)
        {
            return Err(invalid("Session projection author binding"));
        }
        Ok(Self {
            node,
            id,
            opening,
            position,
            name,
            harness,
            named_at,
            ended,
        })
    }
}

/// One retained part's decoded body at an exact bundle offset. Part count is a scalar;
/// the coordinates live in sealed pages and never in a count-sized resident vector.
#[derive(Clone, Copy)]
pub(super) struct Part {
    pub source: Source,
    pub offset: u64,
    pub bytes: u64,
    pub number: u64,
}

impl Part {
    pub fn key(first: &Digest32, offset: u64) -> Key {
        let mut key = [0; 64];
        key[..32].copy_from_slice(first);
        key[32..40].copy_from_slice(&offset.to_be_bytes());
        key
    }

    pub fn put(self, e: &mut Encoder) {
        e.array(4);
        self.source.put(e);
        e.uint(self.offset).uint(self.bytes).uint(self.number);
    }

    pub fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 4 {
            return Err(invalid("Session metadata part arity"));
        }
        let part = Self {
            source: Source::read(d)?,
            offset: d.uint()?,
            bytes: d.uint()?,
            number: d.uint()?,
        };
        if part.number == 0 || part.offset.checked_add(part.bytes).is_none() {
            return Err(invalid("Session metadata part coordinates"));
        }
        Ok(part)
    }
}

fn optional_field(e: &mut Encoder, field: Option<Field>) {
    e.array(usize::from(field.is_some()));
    if let Some(field) = field {
        field.put(e);
    }
}

fn read_optional_field(d: &mut Decoder<'_>) -> Result<Option<Field>> {
    match d.array()? {
        0 => Ok(None),
        1 => Field::read(d).map(Some),
        _ => Err(invalid("Session projection field option")),
    }
}
