//! Streaming interpretation of an envelope. Arbitrary text and opaque JSON are scanned,
//! never retained. Only the envelope's already-bounded identifiers and field coordinates
//! survive the scan. Duplicate object keys keep their last value, as Envelope::parse does.

use crate::error::{Error, Result};
use vox_agentcomms::envelope::{addressee, is_valid_name, is_valid_tag, MAX_NAME, MAX_TAGS};

use super::text::{Input, Reader, StringRef};

#[derive(Default)]
pub(super) struct Metadata {
    pub kind: String,
    pub from: String,
    pub name: Option<StringRef>,
    pub cwd: Option<StringRef>,
    pub harness: Option<StringRef>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ignore,
    Envelope,
    Context,
    Data,
    Session,
    Addresses,
    Tags,
}

#[derive(Default)]
struct Object {
    fields: Metadata,
    // Each bit represents one recognised field. An invalid earlier duplicate is replaced
    // by the later field, rather than poisoning an otherwise valid final object.
    invalid: u16,
    seen: u16,
}

enum Value {
    Null,
    Boolean,
    Number(Option<u64>),
    Text(StringRef),
    Object(Box<Object>),
    Array(bool),
}

fn bad() -> Error {
    Error::MalformedBundle("Session metadata JSON")
}

/// Malformed peer-authored metadata has no Session meaning. A storage failure is propagated
/// separately; callers must not treat missing/corrupt sealed sources as an absent Session.
pub(super) fn parse(source: &mut impl Input) -> Result<Option<Metadata>> {
    match read(source) {
        Ok(value) => Ok(value),
        Err(Error::MalformedBundle(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn read(source: &mut impl Input) -> Result<Option<Metadata>> {
    let mut reader = Reader::new(source, 0)?;
    whitespace(&mut reader)?;
    if reader.peek()? != Some(b'{') {
        return Ok(None);
    }
    let Value::Object(object) = value(&mut reader, Mode::Envelope, 0)? else {
        return Ok(None);
    };
    whitespace(&mut reader)?;
    if reader.peek()?.is_some() || object.invalid != 0 || object.seen & 3 != 3 {
        return Ok(None);
    }
    Ok(Some(object.fields))
}

fn whitespace(reader: &mut Reader<'_, impl Input>) -> Result<()> {
    while matches!(reader.peek()?, Some(b' ' | b'\n' | b'\r' | b'\t')) {
        reader.byte()?;
    }
    Ok(())
}

fn word(reader: &mut Reader<'_, impl Input>, expected: &[u8]) -> Result<()> {
    for byte in expected {
        reader.expect(*byte)?;
    }
    Ok(())
}

fn value(reader: &mut Reader<'_, impl Input>, mode: Mode, depth: usize) -> Result<Value> {
    whitespace(reader)?;
    match reader.peek()?.ok_or_else(bad)? {
        b'n' => {
            word(reader, b"null")?;
            Ok(Value::Null)
        }
        b't' => {
            word(reader, b"true")?;
            Ok(Value::Boolean)
        }
        b'f' => {
            word(reader, b"false")?;
            Ok(Value::Boolean)
        }
        b'"' => reader.string(160).map(Value::Text),
        b'{' => object(reader, mode, depth),
        b'[' => array(reader, mode, depth),
        b'-' | b'0'..=b'9' => number(reader).map(Value::Number),
        _ => Err(bad()),
    }
}

// Use serde_json's existing numeric semantics without building a Value or retaining the
// numeric lexeme. Its ordinary Number decoder holds scalar numeric state, not arbitrary
// precision text. A one-byte reader lets byte_offset restore a looked-ahead delimiter.
fn number<S: Input>(reader: &mut Reader<'_, S>) -> Result<Option<u64>> {
    struct NumberInput<'a, 'b, S> {
        reader: &'a mut Reader<'b, S>,
        error: Option<Error>,
    }
    impl<S: Input> std::io::Read for NumberInput<'_, '_, S> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if out.is_empty() {
                return Ok(0);
            }
            match self.reader.peek() {
                Ok(Some(_)) => match self.reader.byte() {
                    Ok(byte) => {
                        out[0] = byte;
                        Ok(1)
                    }
                    Err(error) => {
                        self.error = Some(error);
                        Err(std::io::Error::other("Session source read failed"))
                    }
                },
                Ok(None) => Ok(0),
                Err(error) => {
                    self.error = Some(error);
                    Err(std::io::Error::other("Session source read failed"))
                }
            }
        }
    }
    let start = reader.position;
    let mut input = NumberInput {
        reader,
        error: None,
    };
    let mut stream =
        serde_json::Deserializer::from_reader(&mut input).into_iter::<serde_json::Number>();
    let result = stream.next();
    let used = stream.byte_offset();
    drop(stream);
    if let Some(error) = input.error {
        return Err(error);
    }
    input.reader.position = start.checked_add(used as u64).ok_or_else(bad)?;
    result
        .ok_or_else(bad)?
        .map(|number| number.as_u64())
        .map_err(|_| bad())
}

fn object(reader: &mut Reader<'_, impl Input>, mode: Mode, depth: usize) -> Result<Value> {
    // serde_json's existing envelope parser rejects nesting at this boundary as well.
    if depth >= 127 {
        return Err(bad());
    }
    reader.expect(b'{')?;
    whitespace(reader)?;
    let mut result = Object::default();
    if reader.peek()? == Some(b'}') {
        reader.byte()?;
        return Ok(Value::Object(Box::new(result)));
    }
    loop {
        let key = reader.string(32)?;
        whitespace(reader)?;
        reader.expect(b':')?;
        let key = key.small.as_deref().unwrap_or_default();
        let child = match (mode, key) {
            (Mode::Envelope, "at") => Mode::Context,
            (Mode::Envelope, "data") => Mode::Data,
            (Mode::Envelope, "to") => Mode::Addresses,
            (Mode::Envelope, "tags") => Mode::Tags,
            (Mode::Data, "session") => Mode::Session,
            _ => Mode::Ignore,
        };
        let parsed = value(reader, child, depth + 1)?;
        property(&mut result, mode, key, parsed);
        whitespace(reader)?;
        match reader.byte()? {
            b'}' => return Ok(Value::Object(Box::new(result))),
            b',' => whitespace(reader)?,
            _ => return Err(bad()),
        }
    }
}

fn array(reader: &mut Reader<'_, impl Input>, mode: Mode, depth: usize) -> Result<Value> {
    if depth >= 127 {
        return Err(bad());
    }
    reader.expect(b'[')?;
    whitespace(reader)?;
    let mut valid = true;
    let mut count = 0usize;
    if reader.peek()? == Some(b']') {
        reader.byte()?;
        return Ok(Value::Array(valid));
    }
    loop {
        let item = value(reader, Mode::Ignore, depth + 1)?;
        count = count.saturating_add(1);
        if matches!(mode, Mode::Addresses | Mode::Tags) {
            valid &= match &item {
                Value::Text(text) => text.small.as_deref().is_some_and(|text| {
                    if mode == Mode::Tags {
                        count <= MAX_TAGS && is_valid_tag(text)
                    } else {
                        let (node, session) = addressee(text);
                        is_valid_name(node, MAX_NAME)
                            && session.is_none_or(|id| is_valid_name(id, MAX_NAME))
                    }
                }),
                _ => false,
            };
        }
        whitespace(reader)?;
        match reader.byte()? {
            b']' => return Ok(Value::Array(valid)),
            b',' => whitespace(reader)?,
            _ => return Err(bad()),
        }
    }
}

fn field(object: &mut Object, bit: u16, valid: bool) {
    object.seen |= bit;
    if valid {
        object.invalid &= !bit;
    } else {
        object.invalid |= bit;
    }
}

fn property(object: &mut Object, mode: Mode, key: &str, value: Value) {
    match mode {
        Mode::Envelope => envelope_property(object, key, value),
        Mode::Context => {
            let bit = match key {
                "repo" => 1,
                "worktree" => 2,
                "branch" => 4,
                "cwd" => 8,
                "session_name" => 16,
                _ => return,
            };
            let valid = matches!(&value, Value::Null | Value::Text(_));
            field(object, bit, valid);
            if key == "session_name" || key == "cwd" {
                let target = if key == "cwd" {
                    &mut object.fields.cwd
                } else {
                    &mut object.fields.name
                };
                *target = match value {
                    Value::Text(text) => Some(text),
                    _ => None,
                };
            }
        }
        Mode::Data if key == "session" => {
            object.fields.harness = match value {
                Value::Object(session) => session.fields.harness,
                _ => None,
            };
        }
        Mode::Session if key == "harness" => {
            object.fields.harness = match value {
                Value::Text(text) => Some(text),
                _ => None,
            };
        }
        _ => {}
    }
}

fn envelope_property(object: &mut Object, key: &str, value: Value) {
    match key {
        "v" => field(object, 1, matches!(value, Value::Number(Some(0 | 1)))),
        "type" | "from" => {
            let bit = if key == "type" { 2 } else { 4 };
            let text = match value {
                Value::Text(text) => text.small,
                _ => None,
            };
            let valid = text
                .as_deref()
                .is_some_and(|s| (key == "from" && s.is_empty()) || is_valid_name(s, MAX_NAME));
            field(object, bit, valid);
            let target = if key == "type" {
                &mut object.fields.kind
            } else {
                &mut object.fields.from
            };
            *target = text.unwrap_or_default();
        }
        "at" => match value {
            Value::Object(context) => {
                field(object, 8, context.invalid == 0);
                object.fields.name = context.fields.name;
                object.fields.cwd = context.fields.cwd;
            }
            _ => {
                field(object, 8, false);
                object.fields.name = None;
                object.fields.cwd = None;
            }
        },
        "data" => {
            object.fields.harness = match value {
                Value::Object(data) => data.fields.harness,
                _ => None,
            };
        }
        "to" => field(object, 16, matches!(value, Value::Array(true))),
        "tags" => field(object, 32, matches!(value, Value::Array(true))),
        "urgent" => field(object, 64, matches!(value, Value::Boolean)),
        "re" => field(object, 128, matches!(value, Value::Text(_) | Value::Null)),
        "thread" => field(object, 256, matches!(value, Value::Text(_) | Value::Null)),
        "hops" => field(
            object,
            512,
            matches!(value, Value::Number(Some(n)) if n <= u64::from(u32::MAX)),
        ),
        "body" => field(object, 1024, matches!(value, Value::Text(_))),
        _ => {}
    }
}
