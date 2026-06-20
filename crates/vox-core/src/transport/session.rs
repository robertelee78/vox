//! The transport **session-establishment** record (ADR-011 §"Downgrade
//! prevention"), canonical struct tag [`StructTag::SessionEstablishment`] =
//! `0x0011`, domain `vox/session-establishment/v1`.
//!
//! After a handshake completes, the negotiated suite + named group are recorded in
//! this record so a downgrade is detectable **end-to-end**, not just at the TLS
//! transcript layer. TLS 1.3's Finished MAC already binds the negotiated group,
//! and Vox offers only the hybrid group, so there is no downgrade target on the
//! wire; this record makes the fact auditable at the application/log layer too
//! (e.g. a peer can later prove which group a session used).
//!
//! Body field order (fixed, canonical-CBOR array): `[peer_id, suite_id,
//! negotiated_group, ts]`:
//! - `peer_id` — the authenticated peer's 32-byte composite-identity fingerprint;
//! - `suite_id` — the ADR-003 ciphersuite id in force (`vox-suite-1` = `0x0001`);
//! - `negotiated_group` — the TLS named-group code point (X25519MLKEM768 =
//!   `0x11EC`); a record whose group is anything else is a downgrade and is
//!   rejected on parse;
//! - `ts` — unix seconds the session was established.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::suite::VOX_SUITE_1;
use crate::transport::provider::X25519MLKEM768_CODE_POINT;
use crate::wire::{self, StructTag};

/// A transport session-establishment record (tag `0x0011`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEstablishment {
    /// The authenticated peer's composite-identity fingerprint.
    pub peer_id: Digest32,
    /// The ADR-003 ciphersuite id in force for the session.
    pub suite_id: u16,
    /// The negotiated TLS named-group code point (must be X25519MLKEM768).
    pub negotiated_group: u16,
    /// Unix seconds at which the session was established.
    pub ts: u64,
}

impl SessionEstablishment {
    /// Build a record for a session negotiated with the Vox default suite
    /// (`vox-suite-1`) over the X25519MLKEM768 group.
    #[must_use]
    pub fn new(peer_id: Digest32, ts: u64) -> Self {
        Self {
            peer_id,
            suite_id: VOX_SUITE_1.id,
            negotiated_group: X25519MLKEM768_CODE_POINT,
            ts,
        }
    }

    /// Encode to the ADR-008-framed canonical wire bytes
    /// (`tag(2) ‖ version(1) ‖ body`).
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .bytes(&self.peer_id)
            .uint(u64::from(self.suite_id))
            .uint(u64::from(self.negotiated_group))
            .uint(self.ts);
        wire::frame(StructTag::SessionEstablishment, &e.finish())
    }

    /// Parse from ADR-008-framed wire bytes.
    ///
    /// Strict: rejects the wrong tag/version, wrong arity, out-of-range u16 fields,
    /// an unknown suite, and — crucially — a `negotiated_group` that is **not**
    /// X25519MLKEM768 (that would be a recorded downgrade, refused here).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let frame = wire::parse_frame(bytes)?;
        if frame.tag != StructTag::SessionEstablishment {
            return Err(Error::UnknownStructTag(frame.tag.as_u16()));
        }
        let mut d = Decoder::new(frame.body);
        if d.array()? != 4 {
            return Err(Error::MalformedBundle("session-establishment arity"));
        }
        let peer_id: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("session-establishment peer_id length"))?;
        let suite_id = u16::try_from(d.uint()?)
            .map_err(|_| Error::MalformedBundle("session-establishment suite_id range"))?;
        let negotiated_group = u16::try_from(d.uint()?)
            .map_err(|_| Error::MalformedBundle("session-establishment group range"))?;
        let ts = d.uint()?;
        d.finish()?;

        // The suite must be in the ADR-003 registry.
        crate::suite::suite_by_id(suite_id)?;
        // The group must be the hybrid PQ group: anything else is a downgrade.
        if negotiated_group != X25519MLKEM768_CODE_POINT {
            return Err(Error::SuiteBelowFloor {
                observed: negotiated_group,
                floor: X25519MLKEM768_CODE_POINT,
            });
        }
        Ok(Self {
            peer_id,
            suite_id,
            negotiated_group,
            ts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let rec = SessionEstablishment::new([0x7Au8; 32], 1_700_000_000);
        let wire = rec.to_wire();
        let back = SessionEstablishment::from_wire(&wire).unwrap();
        assert_eq!(rec, back);
        assert_eq!(back.suite_id, VOX_SUITE_1.id);
        assert_eq!(back.negotiated_group, X25519MLKEM768_CODE_POINT);
    }

    #[test]
    fn rejects_wrong_tag() {
        let rec = SessionEstablishment::new([1u8; 32], 1);
        let mut wire = rec.to_wire();
        // Re-tag as LogEntry (0x0001).
        wire[0] = 0x00;
        wire[1] = 0x01;
        assert!(matches!(
            SessionEstablishment::from_wire(&wire),
            Err(Error::UnknownStructTag(0x0001))
        ));
    }

    #[test]
    fn rejects_recorded_downgrade_group() {
        // Hand-build a record whose negotiated_group is a classical group code
        // point (e.g. X25519 = 0x001D); from_wire must reject it as a downgrade.
        let mut e = Encoder::new();
        e.array(4)
            .bytes(&[2u8; 32])
            .uint(u64::from(VOX_SUITE_1.id))
            .uint(0x001D) // classical X25519 — NOT the hybrid group
            .uint(42);
        let wire = wire::frame(StructTag::SessionEstablishment, &e.finish());
        assert!(matches!(
            SessionEstablishment::from_wire(&wire),
            Err(Error::SuiteBelowFloor {
                observed: 0x001D,
                floor: 0x11EC
            })
        ));
    }

    #[test]
    fn rejects_unknown_suite() {
        let mut e = Encoder::new();
        e.array(4)
            .bytes(&[3u8; 32])
            .uint(0x9999) // unknown suite
            .uint(u64::from(X25519MLKEM768_CODE_POINT))
            .uint(1);
        let wire = wire::frame(StructTag::SessionEstablishment, &e.finish());
        assert!(matches!(
            SessionEstablishment::from_wire(&wire),
            Err(Error::UnknownSuite(0x9999))
        ));
    }

    #[test]
    fn rejects_trailing_and_bad_arity() {
        let mut e = Encoder::new();
        e.array(3).bytes(&[0u8; 32]).uint(1).uint(2);
        let wire = wire::frame(StructTag::SessionEstablishment, &e.finish());
        assert!(SessionEstablishment::from_wire(&wire).is_err());
    }
}
