//! The plaintext **content envelope** a channel message carries inside its
//! ADR-006 sender-key encryption (ADR-016 M13).
//!
//! The log entry (ADR-008) binds author, sequence and channel; the sender-key
//! message (ADR-006) binds the chain and iteration; neither carries a wall-clock
//! time or a content kind, so the plaintext does. Canonical CBOR
//! `[1, kind, created_secs, body]` with `kind = 1` for UTF-8 text. Strictly
//! decoded; the body is capped well below the ADR-008 payload bound so a single
//! message cannot be a multi-megabyte plaintext.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};

/// Envelope version.
const VERSION: u64 = 1;
/// `kind` for a UTF-8 text message.
pub const KIND_TEXT: u64 = 1;
/// Maximum text body length in bytes (64 KiB).
pub const MAX_TEXT_LEN: usize = 64 * 1024;

/// A decoded content envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    /// Wall-clock send time, seconds since the Unix epoch, as the author recorded it.
    pub created_secs: u64,
    /// The message text.
    pub text: String,
}

impl Content {
    /// Encode a text message. Fails if the text exceeds [`MAX_TEXT_LEN`].
    pub fn text(created_secs: u64, text: &str) -> Result<Self> {
        if text.len() > MAX_TEXT_LEN {
            return Err(Error::SizeLimitExceeded("message text"));
        }
        Ok(Self {
            created_secs,
            text: text.to_owned(),
        })
    }

    /// Canonical bytes: `[1, KIND_TEXT, created_secs, text]`.
    #[must_use]
    pub fn to_canonical_vec(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(VERSION)
            .uint(KIND_TEXT)
            .uint(self.created_secs)
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
        let created_secs = d.uint()?;
        let text = d.text()?;
        if text.len() > MAX_TEXT_LEN {
            return Err(Error::SizeLimitExceeded("message text"));
        }
        let text = text.to_owned();
        d.finish()?;
        Ok(Self { created_secs, text })
    }
}
