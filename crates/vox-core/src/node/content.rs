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

/// Envelope version. **2 records the timestamp in milliseconds; 1 recorded seconds.**
///
/// The unit changed rather than the shape: the array is still four elements, so a version-1
/// envelope and a version-2 one differ only in the discriminant and the meaning of the third
/// element. That is deliberate — adding a field would have changed the arity, and a mismatched
/// arity fails as "record rejected" three layers from the cause.
///
/// # Why milliseconds
/// Whole seconds were too coarse for the thing they order. The ADR-020 work board sorts claims by
/// `(timestamp, entry_hash)` and falls back to the hash when timestamps tie — deterministic on
/// every node, but not causal. Two agents claiming the same item act milliseconds apart, so they
/// landed in the same second constantly and the winner was decided by a hash: the agent told "you
/// lost" could end up holding the item. Milliseconds move that tie-break from the common case to
/// the rare one it was designed to be.
const VERSION: u64 = 2;

/// Version 1 of this envelope, whose third element is **seconds**.
///
/// Still decoded, and always will be: entries already in a log were written with it, and a log is
/// append-only. A version-1 timestamp is scaled up on the way in, so everything above this
/// boundary works in one unit.
const VERSION_SECONDS: u64 = 1;

/// Milliseconds per second, for scaling a version-1 timestamp.
const MILLIS_PER_SEC: u64 = 1_000;
/// `kind` for a UTF-8 text message.
pub const KIND_TEXT: u64 = 1;
/// Maximum text body length in bytes (64 KiB).
pub const MAX_TEXT_LEN: usize = 64 * 1024;

/// A decoded content envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    /// Wall-clock send time, **milliseconds** since the Unix epoch, as the author recorded it.
    ///
    /// A version-1 envelope carried seconds; decoding one multiplies by 1000, so a caller never
    /// sees two units. Display and TTL arithmetic divide by 1000 where they want whole seconds.
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

    /// Canonical bytes: `[VERSION, KIND_TEXT, created_millis, text]`. Always written at the
    /// current version; version 1 is a decode-only shape.
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
        // **Both versions decode, and the unit is normalised here** so nothing above this
        // function has to know which one it read. A stricter equality check would make every
        // entry written before this change unreadable, and the log is append-only.
        let version = d.uint()?;
        let scale = match version {
            VERSION => 1,
            VERSION_SECONDS => MILLIS_PER_SEC,
            _ => return Err(Error::MalformedBundle("content envelope version")),
        };
        if d.uint()? != KIND_TEXT {
            return Err(Error::MalformedBundle("content envelope kind"));
        }
        // **Rejected, not clamped.** A version-1 timestamp large enough to overflow when scaled is
        // already nonsense — no real clock produces it — and `saturating_mul` would turn it into
        // `u64::MAX`, which sorts last in the ADR-020 claim order for ever. A record that cannot be
        // represented should fail to decode, not win every tie-break until the end of time. An
        // overflow *panic* is not acceptable either: this is reachable by anyone who can put bytes
        // on a board.
        let raw = d.uint()?;
        let created_millis = raw
            .checked_mul(scale)
            .ok_or(Error::MalformedBundle("content envelope timestamp"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A version-1 envelope, whose timestamp is **seconds**, must decode to the same instant under
    /// a version-2 decoder — as milliseconds.
    ///
    /// This is the golden vector for the one failure mode a version bump with an unchanged arity
    /// has: the decoder reads a *plausible* number rather than erroring. Seconds silently taken as
    /// milliseconds is a 1000× error that renders as 1970 and sorts before every real entry, and
    /// nothing about the frame's shape would reveal it. The bytes below are fixed on purpose — they
    /// are what a node running before this change wrote, and a log is append-only, so this is not a
    /// hypothetical input.
    #[test]
    fn a_version_1_envelope_decodes_as_milliseconds() {
        // `[1, 1, 1_700_000_000, "hello"]` — exactly what the previous version emitted.
        let mut e = Encoder::new();
        e.array(4)
            .uint(VERSION_SECONDS)
            .uint(KIND_TEXT)
            .uint(1_700_000_000)
            .text("hello");
        let v1 = e.finish();

        let got = Content::from_canonical_slice(&v1).expect("a v1 envelope must still decode");
        assert_eq!(
            got.created_millis, 1_700_000_000_000,
            "a v1 timestamp is seconds and must be scaled, not taken as milliseconds"
        );
        assert_eq!(got.text, "hello");
    }

    /// And a version-2 envelope round-trips without scaling.
    #[test]
    fn a_version_2_envelope_round_trips_in_milliseconds() {
        let c = Content::text(1_700_000_000_123, "hello").expect("build");
        let got = Content::from_canonical_slice(&c.to_canonical_vec()).expect("decode");
        assert_eq!(got.created_millis, 1_700_000_000_123);
        assert_eq!(got, c);
    }

    /// The sub-second part must survive, because it is the whole point of the change: two messages
    /// in the same second must not compare equal.
    #[test]
    fn two_messages_in_one_second_are_ordered() {
        let a = Content::text(1_700_000_000_004, "first").expect("build");
        let b = Content::text(1_700_000_000_009, "second").expect("build");
        assert!(
            a.created_millis < b.created_millis,
            "same second, different milliseconds — these must not tie, or the claim order falls \
             back to a hash tie-break and the agent told 'you lost' can end up holding the item"
        );
    }

    /// A version-1 timestamp too large to scale is refused rather than clamped: `u64::MAX` would
    /// sort last in the claim order for ever.
    #[test]
    fn an_unrepresentable_version_1_timestamp_is_refused() {
        // Field order matters here and I got it wrong first: with `u64::MAX` written where `kind`
        // belongs, this passed because the KIND check refused it — a test that never reached the
        // overflow it claims to cover. Asserted below against the *mutation* that proves it: the
        // same bytes with a representable timestamp must DECODE, so the only thing distinguishing
        // the two cases is the timestamp.
        let bytes = |secs: u64| {
            let mut e = Encoder::new();
            e.array(4)
                .uint(VERSION_SECONDS)
                .uint(KIND_TEXT)
                .uint(secs)
                .text("x");
            e.finish()
        };
        assert!(
            Content::from_canonical_slice(&bytes(u64::MAX)).is_err(),
            "a v1 timestamp that cannot be scaled must be refused, not clamped to u64::MAX"
        );
        assert!(
            Content::from_canonical_slice(&bytes(1_700_000_000)).is_ok(),
            "control: the same frame with a representable timestamp must decode, so the refusal \
             above is about the timestamp and not about the frame"
        );
    }
}
