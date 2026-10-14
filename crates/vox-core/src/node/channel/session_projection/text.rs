//! JSON string fields over authenticated bounded records. Neither validation nor output
//! requires an allocation proportional to the field's length.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::hash::Digest32;

use super::record::Field;

const READ_BYTES: usize = 8 * 1024;

/// The concatenated, decoded bodies of a complete Session metadata bundle, or one ordinary
/// envelope. Implementations open one authenticated sealed source row at a time. Missing
/// parts, storage errors and a changed source are errors, never an empty read.
pub(super) trait Input {
    fn len(&self) -> u64;
    fn read_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<usize>;
}

fn invalid(why: &'static str) -> Error {
    Error::MalformedBundle(why)
}

pub(super) struct Reader<'a, S> {
    source: &'a mut S,
    buffer: [u8; READ_BYTES],
    buffer_at: u64,
    used: usize,
    pub position: u64,
}

impl<'a, S: Input> Reader<'a, S> {
    pub fn new(source: &'a mut S, position: u64) -> Result<Self> {
        if position > source.len() {
            return Err(invalid("Session metadata offset"));
        }
        Ok(Self {
            source,
            buffer: [0; READ_BYTES],
            buffer_at: position,
            used: 0,
            position,
        })
    }

    pub fn peek(&mut self) -> Result<Option<u8>> {
        if self.position == self.source.len() {
            return Ok(None);
        }
        let after = self.buffer_at.saturating_add(self.used as u64);
        if self.position < self.buffer_at || self.position >= after {
            self.buffer_at = self.position;
            self.used = self.source.read_at(self.position, &mut self.buffer)?;
            if self.used == 0 || self.used > READ_BYTES {
                return Err(Error::MalformedAtRest(
                    "Session metadata source ended early",
                ));
            }
            if self.position.saturating_add(self.used as u64) > self.source.len() {
                return Err(Error::MalformedAtRest(
                    "Session metadata source exceeded its length",
                ));
            }
        }
        let at = usize::try_from(self.position - self.buffer_at)
            .map_err(|_| invalid("Session metadata buffer offset"))?;
        self.buffer
            .get(at)
            .copied()
            .map(Some)
            .ok_or_else(|| invalid("Session metadata buffer position"))
    }

    pub fn byte(&mut self) -> Result<u8> {
        let byte = self
            .peek()?
            .ok_or_else(|| invalid("Session metadata ended early"))?;
        self.position = self
            .position
            .checked_add(1)
            .ok_or_else(|| invalid("Session metadata offset exhausted"))?;
        Ok(byte)
    }

    pub fn expect(&mut self, expected: u8) -> Result<()> {
        if self.byte()? != expected {
            return Err(invalid("Session metadata syntax"));
        }
        Ok(())
    }

    /// One decoded scalar, or the closing quote. Starting at a byte-page boundary is safe
    /// because a page cursor is returned only after a whole scalar has been consumed.
    pub fn character(&mut self) -> Result<Option<char>> {
        let byte = self.byte()?;
        match byte {
            b'"' => Ok(None),
            b'\\' => self.escape().map(Some),
            0..=0x1f => Err(invalid("Session metadata string control")),
            0x20..=0x7f => Ok(Some(char::from(byte))),
            _ => {
                let count = match byte {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => return Err(invalid("Session metadata UTF-8")),
                };
                let mut bytes = [0; 4];
                bytes[0] = byte;
                for slot in &mut bytes[1..count] {
                    *slot = self.byte()?;
                }
                std::str::from_utf8(&bytes[..count])
                    .ok()
                    .and_then(|s| s.chars().next())
                    .map(Some)
                    .ok_or_else(|| invalid("Session metadata UTF-8"))
            }
        }
    }

    fn hex(&mut self) -> Result<u32> {
        let mut number = 0;
        for _ in 0..4 {
            let digit = match self.byte()? {
                b @ b'0'..=b'9' => u32::from(b - b'0'),
                b @ b'a'..=b'f' => u32::from(b - b'a' + 10),
                b @ b'A'..=b'F' => u32::from(b - b'A' + 10),
                _ => return Err(invalid("Session metadata Unicode escape")),
            };
            number = number * 16 + digit;
        }
        Ok(number)
    }

    fn escape(&mut self) -> Result<char> {
        Ok(match self.byte()? {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let first = self.hex()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    self.expect(b'\\')?;
                    self.expect(b'u')?;
                    let second = self.hex()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(invalid("Session metadata surrogate pair"));
                    }
                    0x10000 + ((first - 0xd800) << 10) + second - 0xdc00
                } else {
                    first
                };
                char::from_u32(scalar).ok_or_else(|| invalid("Session metadata Unicode scalar"))?
            }
            _ => return Err(invalid("Session metadata string escape")),
        })
    }

    /// Validate one field and retain only its coordinates, length and digest. `small`
    /// is for existing bounded identifiers/keys; exceeding it stops retaining text,
    /// without imposing any bound on the underlying field.
    pub fn string(&mut self, small: usize) -> Result<StringRef> {
        let start = self.position;
        self.expect(b'"')?;
        let mut bytes = 0u64;
        let mut hash = Sha256::new();
        let mut saved = Some(String::new());
        while let Some(character) = self.character()? {
            let mut encoded = [0; 4];
            let text = character.encode_utf8(&mut encoded);
            bytes = bytes
                .checked_add(text.len() as u64)
                .ok_or_else(|| invalid("Session metadata length exhausted"))?;
            hash.update(text.as_bytes());
            if let Some(s) = &mut saved {
                if s.len().saturating_add(text.len()) <= small {
                    s.push_str(text);
                } else {
                    saved = None;
                }
            }
        }
        Ok(StringRef {
            start,
            end: self.position,
            bytes,
            hash: hash.finalize().into(),
            small: saved,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct StringRef {
    pub start: u64,
    pub end: u64,
    pub bytes: u64,
    pub hash: Digest32,
    pub small: Option<String>,
}

pub(super) struct TextPage {
    pub bytes: Vec<u8>,
    /// Encoded offset of the next scalar, not a decoded byte offset.
    pub next: Option<u64>,
}

/// Decode only the next byte page of an already validated field. The cursor belongs to
/// a revision-checked field descriptor; callers never turn a changed source into empty text.
pub(super) fn page(
    source: &mut impl Input,
    field: Field,
    after: Option<u64>,
    max_bytes: usize,
) -> Result<TextPage> {
    if max_bytes < 4 || field.end > source.len() {
        return Err(invalid("Session metadata page bound"));
    }
    let first = field
        .start
        .checked_add(1)
        .ok_or_else(|| invalid("Session metadata field offset"))?;
    let at = after.unwrap_or(first);
    if at < first || at >= field.end {
        return Err(invalid("Session metadata page cursor"));
    }
    let mut reader = Reader::new(source, at)?;
    let mut bytes = Vec::with_capacity(max_bytes.min(READ_BYTES));
    loop {
        let next = reader.position;
        let Some(character) = reader.character()? else {
            if reader.position != field.end {
                return Err(invalid("Session metadata field ended early"));
            }
            return Ok(TextPage { bytes, next: None });
        };
        if reader.position >= field.end {
            return Err(invalid("Session metadata field exceeded its range"));
        }
        let mut encoded = [0; 4];
        let text = character.encode_utf8(&mut encoded).as_bytes();
        if bytes.len().saturating_add(text.len()) > max_bytes {
            return Ok(TextPage {
                bytes,
                next: Some(next),
            });
        }
        bytes.extend_from_slice(text);
    }
}
