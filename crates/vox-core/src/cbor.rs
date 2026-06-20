//! Canonical, deterministic CBOR — the single encoding the whole ADR series
//! signs and verifies over (ADR-008).
//!
//! ## Why hand-rolled
//! ADR-008 requires that *two independent implementations produce byte-identical
//! canonical CBOR* — it is a release gate with golden vectors. That guarantee is
//! only as trustworthy as the encoder is auditable, so the canonical subset is
//! specified directly here (as ADR-008 does for the log format itself) rather
//! than depending on a general-purpose CBOR crate whose determinism is a
//! configuration detail. The subset is exactly the value space Vox's signed
//! structures need: unsigned integers, byte strings, text strings, arrays, and
//! maps.
//!
//! ## Canonical rules enforced (RFC 8949 §4.2.1)
//! - **Definite length only.** Indefinite-length items are rejected on decode.
//! - **Shortest-form** integers and length prefixes, on both encode and decode.
//! - **Map keys sorted** by the bytewise lexicographic order of their canonical
//!   encoding, with duplicates rejected.
//! - **No trailing bytes** after the top-level item.
//!
//! ## Why signed structs are CBOR arrays, not maps
//! Vox's signed/authenticated structures (log entries, SKDMs, certs, consent
//! grants, rendezvous records, the TLS identity extension) have a fixed,
//! ordered field schema. They are therefore encoded as definite-length **arrays**
//! in the field order each ADR fixes — the same choice COSE (RFC 9052) makes for
//! canonical signing. Arrays are unambiguously deterministic without any
//! key-ordering question, and are smaller. The map rules above still apply to
//! any map a payload chooses to carry.
//!
//! The signing input for a struct is `domain_sep ‖ canonical_bytes` (ADR-008),
//! where `domain_sep` is the per-struct ASCII label from [`crate::wire`] and
//! `canonical_bytes` is the CBOR produced here. Wire framing (the 2-byte tag and
//! 1-byte version) is applied separately in [`crate::wire`].

use core::fmt;

/// Errors from canonical CBOR encoding/decoding.
///
/// Every decode-side variant represents input a correct, canonical encoder
/// could never have produced — i.e. an attempt to feed a malleable or malformed
/// encoding into a signature/MAC check. They are hard failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CborError {
    /// Input ended before the current item was fully read.
    #[error("unexpected end of input")]
    UnexpectedEof,
    /// Bytes remained after the top-level item (decode expects exactly one).
    #[error("trailing bytes after top-level item")]
    TrailingBytes,
    /// An integer or length used a longer encoding than its value requires.
    #[error("integer not in shortest form")]
    NonCanonicalInt,
    /// An indefinite-length item was encountered (forbidden — not deterministic).
    #[error("indefinite-length item")]
    IndefiniteLength,
    /// Reserved additional-info values 28–30 were used.
    #[error("reserved additional-info value")]
    ReservedAdditionalInfo,
    /// The major type found was not the one the caller required.
    #[error("unexpected major type {got} (wanted {wanted})")]
    UnexpectedMajor {
        /// The major type the reader required.
        wanted: u8,
        /// The major type actually present.
        got: u8,
    },
    /// A text string was not valid UTF-8.
    #[error("invalid utf-8 in text string")]
    InvalidUtf8,
    /// Map keys were not in strictly-ascending canonical order (unsorted or dup).
    #[error("map keys not canonically ordered")]
    UnorderedMapKeys,
    /// A length prefix exceeded the bytes actually available (anti-DoS guard).
    #[error("declared length {len} exceeds remaining input {remaining}")]
    LengthOutOfBounds {
        /// The declared element/byte count.
        len: u64,
        /// Bytes actually remaining in the buffer.
        remaining: usize,
    },
    /// Nesting exceeded [`MAX_DEPTH`].
    #[error("maximum nesting depth exceeded")]
    DepthExceeded,
}

/// Maximum structural nesting depth accepted on decode. Vox's structures are
/// shallow; a deep-nesting input is malformed/hostile, so we cap recursion to
/// keep decoding stack-safe.
pub const MAX_DEPTH: usize = 32;

// CBOR major types (high 3 bits of the initial byte).
const MAJOR_UINT: u8 = 0;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;

// ---------------------------------------------------------------------------
// Low-level canonical writer
// ---------------------------------------------------------------------------

/// Append the canonical CBOR head for `(major, value)` to `out`, choosing the
/// shortest legal encoding.
fn write_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let mt = major << 5;
    if value < 24 {
        out.push(mt | (value as u8));
    } else if value <= u8::MAX as u64 {
        out.push(mt | 24);
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(mt | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(mt | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// A streaming canonical-CBOR writer. Callers emit the fields of a struct in the
/// fixed order their ADR specifies; arrays/maps are opened with an explicit
/// length, so only definite-length output is possible.
#[derive(Debug, Default)]
pub struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    /// Create an empty encoder.
    #[must_use]
    pub fn new() -> Self {
        Self { out: Vec::new() }
    }

    /// Encode an unsigned integer (major type 0), shortest form.
    pub fn uint(&mut self, n: u64) -> &mut Self {
        write_head(&mut self.out, MAJOR_UINT, n);
        self
    }

    /// Encode a byte string (major type 2).
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        write_head(&mut self.out, MAJOR_BYTES, b.len() as u64);
        self.out.extend_from_slice(b);
        self
    }

    /// Encode a text string (major type 3). The input is already valid UTF-8.
    pub fn text(&mut self, s: &str) -> &mut Self {
        write_head(&mut self.out, MAJOR_TEXT, s.len() as u64);
        self.out.extend_from_slice(s.as_bytes());
        self
    }

    /// Emit an array header of `len` items. The caller then emits exactly `len`
    /// items.
    pub fn array(&mut self, len: usize) -> &mut Self {
        write_head(&mut self.out, MAJOR_ARRAY, len as u64);
        self
    }

    /// Finish, returning the canonical bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.out
    }

    /// Borrow the bytes written so far.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.out
    }
}

// ---------------------------------------------------------------------------
// Low-level canonical reader (strict)
// ---------------------------------------------------------------------------

/// A strict canonical-CBOR reader. Every method rejects input a canonical
/// encoder could not have produced.
#[derive(Debug)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Wrap a byte slice for decoding.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self.pos.checked_add(n).ok_or(CborError::UnexpectedEof)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(CborError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, CborError> {
        Ok(self.take(1)?[0])
    }

    /// Read one canonical head, returning `(major, argument)`. Enforces
    /// shortest-form arguments and rejects indefinite/reserved forms.
    fn read_head(&mut self) -> Result<(u8, u64), CborError> {
        let initial = self.read_u8()?;
        let major = initial >> 5;
        let ai = initial & 0x1f;
        let value = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.read_u8()?);
                if v < 24 {
                    return Err(CborError::NonCanonicalInt);
                }
                v
            }
            25 => {
                let b = self.take(2)?;
                let v = u64::from(u16::from_be_bytes([b[0], b[1]]));
                if v <= u8::MAX as u64 {
                    return Err(CborError::NonCanonicalInt);
                }
                v
            }
            26 => {
                let b = self.take(4)?;
                let v = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                if v <= u16::MAX as u64 {
                    return Err(CborError::NonCanonicalInt);
                }
                v
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if v <= u32::MAX as u64 {
                    return Err(CborError::NonCanonicalInt);
                }
                v
            }
            28..=30 => return Err(CborError::ReservedAdditionalInfo),
            // ai == 31
            _ => return Err(CborError::IndefiniteLength),
        };
        Ok((major, value))
    }

    fn expect_head(&mut self, wanted: u8) -> Result<u64, CborError> {
        let (got, value) = self.read_head()?;
        if got != wanted {
            return Err(CborError::UnexpectedMajor { wanted, got });
        }
        Ok(value)
    }

    /// Read an unsigned integer (major type 0).
    pub fn uint(&mut self) -> Result<u64, CborError> {
        self.expect_head(MAJOR_UINT)
    }

    /// Read a byte string (major type 2), returning a borrowed slice.
    pub fn bytes(&mut self) -> Result<&'a [u8], CborError> {
        let len = self.expect_head(MAJOR_BYTES)?;
        self.checked_len(len)?;
        self.take(len as usize)
    }

    /// Read a text string (major type 3), validating UTF-8.
    pub fn text(&mut self) -> Result<&'a str, CborError> {
        let len = self.expect_head(MAJOR_TEXT)?;
        self.checked_len(len)?;
        let raw = self.take(len as usize)?;
        core::str::from_utf8(raw).map_err(|_| CborError::InvalidUtf8)
    }

    /// Read an array header (major type 4), returning the element count.
    pub fn array(&mut self) -> Result<usize, CborError> {
        let len = self.expect_head(MAJOR_ARRAY)?;
        self.checked_len(len)?;
        Ok(len as usize)
    }

    // NOTE: there is deliberately no low-level `map()` reader. Every *signed*
    // Vox struct is a CBOR array (see module docs), and a bare `map()` that
    // returns only a pair count cannot enforce canonical key ordering, so it
    // would be a malleability footgun. Dynamic maps go through [`Value`], whose
    // decoder enforces strictly-ascending canonical key order.

    /// Guard a declared length against the bytes actually remaining, so a hostile
    /// length prefix cannot trigger a huge allocation before EOF is hit.
    fn checked_len(&self, len: u64) -> Result<(), CborError> {
        if len > self.remaining() as u64 {
            return Err(CborError::LengthOutOfBounds {
                len,
                remaining: self.remaining(),
            });
        }
        Ok(())
    }

    /// Assert the input is fully consumed. Call after the top-level item.
    pub fn finish(self) -> Result<(), CborError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CborError::TrailingBytes)
        }
    }
}

// ---------------------------------------------------------------------------
// Dynamic value model (used for tests, golden vectors, and any dynamic payload)
// ---------------------------------------------------------------------------

/// A decoded/encodable canonical CBOR value.
///
/// The fixed-schema signed structs use the [`Encoder`]/[`Decoder`] primitives
/// directly; `Value` is the dynamic counterpart, and the one place map
/// canonicalisation lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Unsigned integer (major type 0).
    Uint(u64),
    /// Byte string (major type 2).
    Bytes(Vec<u8>),
    /// Text string (major type 3).
    Text(String),
    /// Array (major type 4).
    Array(Vec<Value>),
    /// Map (major type 5); canonicalised (sorted, dedup) on encode.
    Map(Vec<(Value, Value)>),
}

impl Value {
    /// Encode to canonical bytes, sorting map keys and rejecting duplicates.
    pub fn to_canonical_vec(&self) -> Result<Vec<u8>, CborError> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CborError> {
        match self {
            Value::Uint(n) => write_head(out, MAJOR_UINT, *n),
            Value::Bytes(b) => {
                write_head(out, MAJOR_BYTES, b.len() as u64);
                out.extend_from_slice(b);
            }
            Value::Text(s) => {
                write_head(out, MAJOR_TEXT, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Array(items) => {
                write_head(out, MAJOR_ARRAY, items.len() as u64);
                for item in items {
                    item.encode_into(out)?;
                }
            }
            Value::Map(pairs) => {
                // Canonical map: sort by encoded-key bytes, reject duplicates.
                let mut encoded: Vec<(Vec<u8>, &Value)> = Vec::with_capacity(pairs.len());
                for (k, v) in pairs {
                    let mut kb = Vec::new();
                    k.encode_into(&mut kb)?;
                    encoded.push((kb, v));
                }
                encoded.sort_by(|a, b| a.0.cmp(&b.0));
                for w in encoded.windows(2) {
                    if w[0].0 == w[1].0 {
                        return Err(CborError::UnorderedMapKeys);
                    }
                }
                write_head(out, MAJOR_MAP, pairs.len() as u64);
                for (kb, v) in encoded {
                    out.extend_from_slice(&kb);
                    v.encode_into(out)?;
                }
            }
        }
        Ok(())
    }

    /// Decode exactly one canonical value from `buf`, requiring no trailing bytes.
    pub fn from_canonical_slice(buf: &[u8]) -> Result<Value, CborError> {
        let mut d = Decoder::new(buf);
        let v = Self::decode(&mut d, 0)?;
        d.finish()?;
        Ok(v)
    }

    fn decode(d: &mut Decoder<'_>, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::DepthExceeded);
        }
        let (major, arg) = d.read_head()?;
        match major {
            MAJOR_UINT => Ok(Value::Uint(arg)),
            MAJOR_BYTES => {
                d.checked_len(arg)?;
                Ok(Value::Bytes(d.take(arg as usize)?.to_vec()))
            }
            MAJOR_TEXT => {
                d.checked_len(arg)?;
                let raw = d.take(arg as usize)?;
                let s = core::str::from_utf8(raw).map_err(|_| CborError::InvalidUtf8)?;
                Ok(Value::Text(s.to_owned()))
            }
            MAJOR_ARRAY => {
                d.checked_len(arg)?;
                let mut items = Vec::with_capacity(arg as usize);
                for _ in 0..arg {
                    items.push(Self::decode(d, depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            MAJOR_MAP => {
                d.checked_len(arg.saturating_mul(2))?;
                let mut pairs: Vec<(Value, Value)> = Vec::with_capacity(arg as usize);
                let mut prev_key: Option<Vec<u8>> = None;
                for _ in 0..arg {
                    let k = Self::decode(d, depth + 1)?;
                    // Enforce strictly-ascending canonical key order on decode.
                    let kb = k.to_canonical_vec()?;
                    if let Some(prev) = &prev_key {
                        if *prev >= kb {
                            return Err(CborError::UnorderedMapKeys);
                        }
                    }
                    prev_key = Some(kb);
                    let v = Self::decode(d, depth + 1)?;
                    pairs.push((k, v));
                }
                Ok(Value::Map(pairs))
            }
            other => Err(CborError::UnexpectedMajor {
                wanted: MAJOR_UINT,
                got: other,
            }),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Uint(n) => write!(f, "{n}"),
            Value::Bytes(b) => write!(f, "h'{}'", hex_lower(b)),
            Value::Text(s) => write!(f, "{s:?}"),
            Value::Array(a) => {
                write!(f, "[")?;
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{v}")?;
                }
                write!(f, "]")
            }
            Value::Map(m) => {
                write!(f, "{{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{k}: {v}")?;
                }
                write!(f, "}}")
            }
        }
    }
}

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('?'));
        s.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('?'));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Golden vectors: byte-exact, verifiable against RFC 8949 by hand. ----

    #[test]
    fn uint_golden_shortest_form() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (23, &[0x17]),
            (24, &[0x18, 0x18]),
            (255, &[0x18, 0xff]),
            (256, &[0x19, 0x01, 0x00]),
            (65535, &[0x19, 0xff, 0xff]),
            (65536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
            (4294967295, &[0x1a, 0xff, 0xff, 0xff, 0xff]),
            (
                4294967296,
                &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
        ];
        for (n, expect) in cases {
            let mut e = Encoder::new();
            e.uint(*n);
            assert_eq!(e.finish(), *expect, "uint {n}");
        }
    }

    #[test]
    fn bytes_text_array_golden() {
        let mut e = Encoder::new();
        e.bytes(&[0x01, 0x02, 0x03]);
        assert_eq!(e.finish(), [0x43, 0x01, 0x02, 0x03]);

        let mut e = Encoder::new();
        e.text("vox");
        assert_eq!(e.finish(), [0x63, b'v', b'o', b'x']);

        // [1, h'aa'] -> array(2), uint 1, bytes len1 0xaa
        let mut e = Encoder::new();
        e.array(2).uint(1).bytes(&[0xaa]);
        assert_eq!(e.finish(), [0x82, 0x01, 0x41, 0xaa]);
    }

    #[test]
    fn empty_byte_and_text() {
        let mut e = Encoder::new();
        e.bytes(&[]);
        assert_eq!(e.finish(), [0x40]);
        let mut e = Encoder::new();
        e.text("");
        assert_eq!(e.finish(), [0x60]);
    }

    // ---- Round-trips through the Value model. ----

    #[test]
    fn value_roundtrip() {
        let v = Value::Array(vec![
            Value::Uint(1),
            Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
            Value::Text("hello".into()),
            Value::Array(vec![Value::Uint(256), Value::Uint(0)]),
        ]);
        let bytes = v.to_canonical_vec().unwrap();
        let back = Value::from_canonical_slice(&bytes).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn map_is_sorted_by_encoded_key() {
        // Keys deliberately out of order; canonical encoding must reorder them
        // to 1, 2, 10 (ascending encoded-key bytes).
        let v = Value::Map(vec![
            (Value::Uint(10), Value::Text("ten".into())),
            (Value::Uint(1), Value::Text("one".into())),
            (Value::Uint(2), Value::Text("two".into())),
        ]);
        let bytes = v.to_canonical_vec().unwrap();
        // map(3): 0xa3 ; then 01 .., 02 .., 0a ..
        assert_eq!(bytes[0], 0xa3);
        assert_eq!(bytes[1], 0x01);
        // Decoding yields keys in canonical (sorted) order.
        let back = Value::from_canonical_slice(&bytes).unwrap();
        if let Value::Map(pairs) = back {
            let keys: Vec<&Value> = pairs.iter().map(|(k, _)| k).collect();
            assert_eq!(
                keys,
                vec![&Value::Uint(1), &Value::Uint(2), &Value::Uint(10)]
            );
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn map_duplicate_keys_rejected_on_encode() {
        let v = Value::Map(vec![
            (Value::Uint(1), Value::Uint(1)),
            (Value::Uint(1), Value::Uint(2)),
        ]);
        assert_eq!(v.to_canonical_vec(), Err(CborError::UnorderedMapKeys));
    }

    // ---- Strictness: every non-canonical form must be rejected on decode. ----

    #[test]
    fn rejects_non_shortest_int() {
        // 0x18 0x05 encodes 5 in two bytes; 5 must be a single byte 0x05.
        assert_eq!(
            Value::from_canonical_slice(&[0x18, 0x05]),
            Err(CborError::NonCanonicalInt)
        );
        // 0x19 0x00 0x10 encodes 16 in three bytes; not shortest.
        assert_eq!(
            Value::from_canonical_slice(&[0x19, 0x00, 0x10]),
            Err(CborError::NonCanonicalInt)
        );
    }

    #[test]
    fn rejects_indefinite_length() {
        // 0x9f = array, indefinite length.
        assert_eq!(
            Value::from_canonical_slice(&[0x9f, 0x01, 0xff]),
            Err(CborError::IndefiniteLength)
        );
    }

    #[test]
    fn rejects_reserved_additional_info() {
        assert_eq!(
            Value::from_canonical_slice(&[0x1c]),
            Err(CborError::ReservedAdditionalInfo)
        );
    }

    #[test]
    fn rejects_trailing_bytes() {
        assert_eq!(
            Value::from_canonical_slice(&[0x01, 0x02]),
            Err(CborError::TrailingBytes)
        );
    }

    #[test]
    fn rejects_unsorted_map_on_decode() {
        // map(2) with keys 2 then 1 — descending, must be rejected.
        let bytes = [0xa2, 0x02, 0x00, 0x01, 0x00];
        assert_eq!(
            Value::from_canonical_slice(&bytes),
            Err(CborError::UnorderedMapKeys)
        );
    }

    #[test]
    fn rejects_truncated_input() {
        // bytes header claims 4 bytes, only 1 present.
        assert!(matches!(
            Value::from_canonical_slice(&[0x44, 0xaa]),
            Err(CborError::LengthOutOfBounds { .. })
        ));
    }

    #[test]
    fn decoder_borrows_without_copy() {
        let mut e = Encoder::new();
        e.array(2).bytes(b"abc").uint(7);
        let buf = e.finish();
        let mut d = Decoder::new(&buf);
        assert_eq!(d.array().unwrap(), 2);
        assert_eq!(d.bytes().unwrap(), b"abc");
        assert_eq!(d.uint().unwrap(), 7);
        d.finish().unwrap();
    }

    #[test]
    fn wrong_major_type_is_reported() {
        let mut e = Encoder::new();
        e.uint(1);
        let buf = e.finish();
        let mut d = Decoder::new(&buf);
        assert_eq!(
            d.bytes().unwrap_err(),
            CborError::UnexpectedMajor { wanted: 2, got: 0 }
        );
    }
}
