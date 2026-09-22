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
//! **What `negotiated_group` is, exactly.** It is a compile-time constant, written
//! unconditionally by [`SessionEstablishment::new`]. Nothing downstream of our own
//! configuration is consulted, so the field would read `X25519MLKEM768` just as
//! confidently if a handshake had used something else. It records **the group this
//! build offers**, and the module heading's "prove which group a session used"
//! overstated it.
//!
//! This is a defect in the evidence, not in the cryptography, and the distinction
//! matters because the record's whole job is to be independent evidence. The
//! guarantee itself holds without this field: the provider offers exactly one
//! `kx_group` so there is no downgrade target,
//! `provider::assert_pq_only` enforces that at every config
//! boundary, and TLS 1.3 binds the negotiated parameters into the Finished MAC, so a
//! mismatch breaks the handshake rather than passing quietly. Nobody's traffic is at
//! risk; the audit record is simply restating our intent under a name that reads like
//! an observation.
//!
//! Making it an observation needs the value rustls already holds: quinn 0.11 gates
//! `negotiated_key_exchange_group` behind a test-only cfg, so it is not reachable
//! from a `Connection` today. Until it is, this field MUST NOT be cited as evidence
//! of what a session negotiated.
//!
//! Body field order (fixed, canonical-CBOR array): `[peer_id, suite_id,
//! negotiated_group, ts]`:
//! - `peer_id` — the authenticated peer's 32-byte composite-identity fingerprint;
//! - `suite_id` — the ADR-003 ciphersuite id in force (`vox-suite-1` = `0x0001`);
//! - `negotiated_group` — the TLS named-group code point (X25519MLKEM768 =
//!   `0x11EC`). **This build writes the group it offers, not a group it observed.**
//!   See the note below; a record whose group is anything else is rejected on parse,
//!   which bites for a record from elsewhere and can never fire for one of ours;
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
    /// The TLS named-group code point this build **offers** (X25519MLKEM768).
    ///
    /// Not an observation of the handshake — see the module docs. The name is the
    /// wire field's, which is why it has not been changed; the documentation is where
    /// the correction belongs.
    pub negotiated_group: u16,
    /// Unix seconds at which the session was established.
    pub ts: u64,
}

impl SessionEstablishment {
    /// Build a record for a session negotiated with the Vox default suite
    /// (`vox-suite-1`) over the X25519MLKEM768 group.
    ///
    /// `negotiated_group` is filled from the constant, unconditionally: this
    /// constructor has no access to what the handshake actually chose. See the module
    /// docs before citing the field as evidence.
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
