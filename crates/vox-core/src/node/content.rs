//! The plaintext **content envelope** a channel message carries inside its
//! ADR-006 sender-key encryption (ADR-016 M13).
//!
//! The log entry (ADR-008) binds author, sequence and channel; the sender-key
//! message (ADR-006) binds the chain and iteration; neither carries a wall-clock
//! time or a content kind, so the plaintext does. Canonical CBOR
//! `[version, kind, created_millis, body]` with `kind = 1` for UTF-8 text. Strictly
//! decoded; the body is capped well below the ADR-008 payload bound so a single
//! message cannot be a multi-megabyte plaintext.
//!
//! `kind = 2` is a **read record** (ADR-028 §6): `[version, 2, created_millis, [entry hash, …]]`,
//! the entries its author was shown since its last record, strictly ascending. Sealed like any
//! message, so only a member holding its author's sender key can open it (RR-2, RR-3), and never
//! a row of the timeline (RR-4).
//!
//! `kind = 3` is a **Session entry** (ADR-029 SC-1, SC-2): `[version, 3, created_millis, [session
//! id, body]]`, one item of a harness session's activity. It is sealed under its node's **drive
//! key** ([`crate::node::drive`]), never its sender key, so only members its node trusts with
//! drive open it; and it is never a row of the room's timeline (SC-4).

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;

/// Envelope version. **2 records the timestamp in milliseconds**, and is the only version this
/// build reads: version 1, which recorded seconds, was an earlier release's (#423).
///
/// # Why milliseconds
/// Whole seconds were too coarse for the thing they order. The ADR-020 work board sorts claims by
/// `(timestamp, entry_hash)` and falls back to the hash when timestamps tie — deterministic on
/// every node, but not causal. Two agents claiming the same item act milliseconds apart, so they
/// landed in the same second constantly and the winner was decided by a hash: the agent told "you
/// lost" could end up holding the item. Milliseconds move that tie-break from the common case to
/// the rare one it was designed to be.
const VERSION: u64 = 2;

/// `kind` for a UTF-8 text message.
pub const KIND_TEXT: u64 = 1;
/// Maximum text body length in bytes (64 KiB).
pub const MAX_TEXT_LEN: usize = 64 * 1024;
/// `kind` for a read record (ADR-028 RR-2).
pub const KIND_READ: u64 = 2;
/// The most entries one read record names. More wait for the next record: at 34 bytes a hash this
/// keeps a record about 35 KB, inside a message's bound.
pub const MAX_READ_HASHES: usize = 1024;

/// `kind` for a Session entry (ADR-029 SC-1).
pub const KIND_SESSION: u64 = 3;
/// The longest session id a Session entry carries, in bytes: a harness's own id is far shorter.
pub const MAX_SESSION_ID_LEN: usize = 256;

/// A decoded Session entry (ADR-029 SC-1): one item of a harness session's activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEntry {
    /// Wall-clock send time, milliseconds since the Unix epoch, as the author recorded it.
    pub created_millis: u64,
    /// The harness's own session id (SE-2).
    pub session_id: String,
    /// The activity item, in the harnesses' shared format; Vox carries it as it is.
    pub body: String,
}

impl SessionEntry {
    /// An entry of `session_id`. Fails on an empty or overlong id, or a body over
    /// [`MAX_TEXT_LEN`]: longer content is split across entries (SC-1).
    pub fn new(created_millis: u64, session_id: &str, body: &str) -> Result<Self> {
        if session_id.is_empty() || session_id.len() > MAX_SESSION_ID_LEN {
            return Err(Error::MalformedBundle("session id"));
        }
        if body.len() > MAX_TEXT_LEN {
            return Err(Error::SizeLimitExceeded("session entry"));
        }
        Ok(Self {
            created_millis,
            session_id: session_id.to_owned(),
            body: body.to_owned(),
        })
    }

    /// Canonical bytes: `[VERSION, KIND_SESSION, created_millis, [session id, body]]`.
    #[must_use]
    pub fn to_canonical_vec(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(VERSION)
            .uint(KIND_SESSION)
            .uint(self.created_millis)
            .array(2)
            .text(&self.session_id)
            .text(&self.body);
        e.finish()
    }
}

/// A decoded content envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    /// Wall-clock send time, **milliseconds** since the Unix epoch, as the author recorded it.
    /// Display and TTL arithmetic divide by 1000 where they want whole seconds.
    pub created_millis: u64,
    /// The message text.
    pub text: String,
}

impl Content {
    /// Encode a text message. Fails if the text exceeds [`MAX_TEXT_LEN`].
    pub fn text(created_millis: u64, text: &str) -> Result<Self> {
        if text.len() > MAX_TEXT_LEN {
            return Err(Error::SizeLimitExceeded("message text"));
        }
        Ok(Self {
            created_millis,
            text: text.to_owned(),
        })
    }

    /// Canonical bytes: `[VERSION, KIND_TEXT, created_millis, text]`.
    #[must_use]
    pub fn to_canonical_vec(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(VERSION)
            .uint(KIND_TEXT)
            .uint(self.created_millis)
            .text(&self.text);
        e.finish()
    }

    /// Strict decode.
    pub fn from_canonical_slice(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        if d.array()? != 4 {
            return Err(Error::MalformedBundle("content envelope arity"));
        }
        if d.uint()? != VERSION {
            return Err(Error::MalformedBundle("content envelope version"));
        }
        if d.uint()? != KIND_TEXT {
            return Err(Error::MalformedBundle("content envelope kind"));
        }
        let created_millis = d.uint()?;
        let text = d.text()?;
        if text.len() > MAX_TEXT_LEN {
            return Err(Error::SizeLimitExceeded("message text"));
        }
        let text = text.to_owned();
        d.finish()?;
        Ok(Self {
            created_millis,
            text,
        })
    }
}

/// A decoded read record (ADR-028 RR-2): the entries its author was shown since its last one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRecord {
    /// Wall-clock send time, milliseconds since the Unix epoch, as the author recorded it.
    pub created_millis: u64,
    /// The entry hashes read, strictly ascending, at most [`MAX_READ_HASHES`].
    pub read: Vec<Digest32>,
}

impl ReadRecord {
    /// A record of `read`, sorted and deduplicated. Fails if it is empty or names more than
    /// [`MAX_READ_HASHES`] entries.
    pub fn new(created_millis: u64, mut read: Vec<Digest32>) -> Result<Self> {
        read.sort_unstable();
        read.dedup();
        if read.is_empty() {
            return Err(Error::MalformedBundle("read record names no entry"));
        }
        if read.len() > MAX_READ_HASHES {
            return Err(Error::SizeLimitExceeded("read record"));
        }
        Ok(Self {
            created_millis,
            read,
        })
    }

    /// Canonical bytes: `[VERSION, KIND_READ, created_millis, [hash, …]]`.
    #[must_use]
    pub fn to_canonical_vec(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(VERSION)
            .uint(KIND_READ)
            .uint(self.created_millis)
            .array(self.read.len());
        for h in &self.read {
            e.bytes(h);
        }
        e.finish()
    }
}

/// What a sealed content plaintext holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// A message ([`KIND_TEXT`]).
    Text(Content),
    /// A read record ([`KIND_READ`]).
    Read(ReadRecord),
    /// A Session entry ([`KIND_SESSION`]).
    Session(SessionEntry),
}

/// Strict decode of either kind of content envelope.
pub fn decode(bytes: &[u8]) -> Result<Decoded> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 4 {
        return Err(Error::MalformedBundle("content envelope arity"));
    }
    if d.uint()? != VERSION {
        return Err(Error::MalformedBundle("content envelope version"));
    }
    match d.uint()? {
        KIND_TEXT => Content::from_canonical_slice(bytes).map(Decoded::Text),
        KIND_READ => {
            let created_millis = d.uint()?;
            let n = d.array()?;
            if n == 0 || n > MAX_READ_HASHES {
                return Err(Error::MalformedBundle("read record length"));
            }
            let mut read: Vec<Digest32> = Vec::with_capacity(n);
            for _ in 0..n {
                let h: Digest32 = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("read record entry hash"))?;
                // Strictly ascending: one encoding per record, no duplicates.
                if read.last().is_some_and(|last| *last >= h) {
                    return Err(Error::MalformedBundle("read record order"));
                }
                read.push(h);
            }
            d.finish()?;
            Ok(Decoded::Read(ReadRecord {
                created_millis,
                read,
            }))
        }
        KIND_SESSION => {
            let created_millis = d.uint()?;
            if d.array()? != 2 {
                return Err(Error::MalformedBundle("session entry arity"));
            }
            let session_id = d.text()?;
            let body = d.text()?;
            d.finish()?;
            SessionEntry::new(created_millis, session_id, body).map(Decoded::Session)
        }
        _ => Err(Error::MalformedBundle("content envelope kind")),
    }
}
