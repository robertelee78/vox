//! The plaintext **content envelope** a channel message carries inside its
//! ADR-006 sender-key encryption (ADR-016 M13).
//!
//! The log entry (ADR-008) binds author, sequence and channel; the sender-key
//! message (ADR-006) binds the chain and iteration; neither carries a wall-clock
//! time or a content kind, so the plaintext does. Canonical CBOR
//! `[version, kind, created_millis, body]` with `kind = 1` for UTF-8 text. Strictly
//! decoded; the body is capped well below the ADR-008 payload bound so a single
//! message cannot be a multi-megabyte plaintext.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};

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
