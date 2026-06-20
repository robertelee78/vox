//! The ratchet message wire struct and the one-time-prekey reuse tracker.
//!
//! Split out of [`crate::pairwise::session`] so the session state machine and the
//! wire/bookkeeping types stay individually small. Like the PQXDH initial message
//! ([`crate::pairwise::init_message`]), a [`Message`] is a *payload* under its own
//! domain label, not an ADR-008 log struct.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::pairwise::header::{RatchetHeader, RATCHET_MSG_DOMAIN};
use crate::suite::algo;

/// A ratchet message on the wire (ADR-004 §Wire): the cleartext header and the
/// AEAD ciphertext. A canonical-CBOR body under [`RATCHET_MSG_DOMAIN`] — a
/// payload, not an ADR-008 log struct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The cleartext ratchet header (bound into the AEAD associated data).
    pub header: RatchetHeader,
    /// The AEAD ciphertext (AES-256-GCM: ciphertext ‖ 16-byte tag).
    pub ciphertext: Vec<u8>,
}

impl Message {
    /// Canonical-CBOR body: `[header_body, ciphertext]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2)
            .bytes(&self.header.canonical_body())
            .bytes(&self.ciphertext);
        e.finish()
    }

    /// Frame for the wire as `RATCHET_MSG_DOMAIN ‖ body`.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let body = self.canonical_body();
        let mut out = Vec::with_capacity(RATCHET_MSG_DOMAIN.len() + body.len());
        out.extend_from_slice(RATCHET_MSG_DOMAIN.as_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Parse a wire-framed ratchet message, rejecting a wrong domain label.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let body = bytes
            .strip_prefix(RATCHET_MSG_DOMAIN.as_bytes())
            .ok_or(Error::MalformedBundle("ratchet-msg domain label"))?;
        let mut d = Decoder::new(body);
        if d.array()? != 2 {
            return Err(Error::MalformedBundle("ratchet-msg arity"));
        }
        let header = RatchetHeader::from_canonical_body(d.bytes()?)?;
        let ciphertext = d.bytes()?.to_vec();
        d.finish()?;
        Ok(Self { header, ciphertext })
    }
}

/// Recipient-side one-time-prekey reuse detector (ADR-004 §Prekey publication).
///
/// A serverless overlay has no atomic arbiter to guarantee each one-time prekey
/// is consumed once; two initiators may race. This tracker records the
/// one-time-prekey ids a recipient has accepted; [`observe`](Self::observe)
/// returns `true` when an id is seen a *second* time, so the caller can flag the
/// session last-resort-grade and surface the reuse. The first use is never
/// downgraded.
#[derive(Debug, Default)]
pub struct OtpReuseTracker {
    seen: std::collections::HashSet<u64>,
}

impl OtpReuseTracker {
    /// A fresh tracker with no observed prekeys.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observed one-time-prekey id, returning `true` if it was already
    /// seen (i.e. this is a reuse and the session should be last-resort-grade).
    pub fn observe(&mut self, prekey_id: u64) -> bool {
        !self.seen.insert(prekey_id)
    }

    /// Whether `prekey_id` has been observed at least once.
    #[must_use]
    pub fn has_seen(&self, prekey_id: u64) -> bool {
        self.seen.contains(&prekey_id)
    }
}

/// The X25519 curve algorithm id in force for ratchet headers (re-exported for
/// callers that build/inspect [`RatchetHeader`]s directly).
pub const RATCHET_CURVE_ALGO: u16 = algo::X25519;

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> RatchetHeader {
        RatchetHeader {
            ratchet_pubkey: [4u8; 32],
            pn: 1,
            n: 2,
            curve_algo: algo::X25519,
            aead_algo: algo::AES_256_GCM,
        }
    }

    #[test]
    fn message_wire_round_trips() {
        let m = Message {
            header: header(),
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(Message::from_wire(&m.to_wire()).unwrap(), m);
    }

    #[test]
    fn message_rejects_wrong_domain() {
        let m = Message {
            header: header(),
            ciphertext: vec![1, 2, 3],
        };
        let mut wrong = b"vox/nope/v1".to_vec();
        wrong.extend_from_slice(&m.canonical_body());
        assert!(matches!(
            Message::from_wire(&wrong),
            Err(Error::MalformedBundle(_))
        ));
    }

    #[test]
    fn otp_reuse_tracker_flags_second_use_only() {
        let mut t = OtpReuseTracker::new();
        assert!(!t.observe(7)); // first use: not a reuse
        assert!(t.observe(7)); // second use: reuse
        assert!(t.has_seen(7));
        assert!(!t.has_seen(8));
        assert!(!t.observe(8)); // distinct id, first use
    }
}
