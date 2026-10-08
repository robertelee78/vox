//! The **admission notice** (tag `0x0020`, domain `vox/admission-notice/v1`), #520: a newcomer's
//! composite key with the join witness its admitting member signed, put on rendezvous boards so
//! every member of the room learns of the newcomer while the newcomer is offline.
//!
//! A member learned of a newcomer from the newcomer's own bundle record (ADR-016 M17.6), which
//! only the newcomer can sign and which lapses. A board keeps it in memory, so an admitting member
//! that restarted while the newcomer was offline held nothing to pass on, and the room's members
//! never agreed on who was in it (the decider, 2026-10-06: every member is to learn of an admitted
//! newcomer, offline or not; who reads whom does not change).
//!
//! The notice is the evidence the bundle already carried, without the bundle: the witness binds
//! the room, the epoch and the joiner's fingerprint under the admitting member's signature, and the
//! key is checked against that fingerprint. It needs no signature of its own, so any member can
//! pass it on, and it is evidence only where the witness's signer is already admitted, which roots
//! every chain in the room's creator, as for a bundle.
//!
//! **It never admits a member that left.** A member's withdraw (`nat::withdraw`, scope member),
//! which the leaver signs, refuses every admission of it witnessed no later than the withdraw, on
//! a board and on a member alike; members keep and pass on withdraws as they do notices, so a
//! notice replayed after a leave admits nothing anywhere the withdraw has reached, and the
//! withdraw travels wherever the notice does.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_PUB_LEN};
use crate::identity::composite::CompositePublicKey;
use crate::nat::record::JoinWitness;
use crate::wire::{frame, parse_frame, StructTag};

/// A newcomer's admission, as its admitting member witnessed it.
#[derive(Debug, Clone)]
pub struct AdmissionNotice {
    /// The newcomer's composite public key; its fingerprint is the witness's `joiner_id`.
    pub key: CompositePublicKey,
    /// The admitting member's witness.
    pub witness: JoinWitness,
}

impl AdmissionNotice {
    /// The notice for `key`, admitted under `witness`. Refused when the witness names another
    /// joiner.
    pub fn new(key: CompositePublicKey, witness: JoinWitness) -> Result<Self> {
        if key.fingerprint() != witness.joiner_id {
            return Err(Error::MalformedRendezvous(
                "admission notice key is not the witnessed joiner",
            ));
        }
        Ok(Self { key, witness })
    }

    /// The room.
    #[must_use]
    pub fn channel_id(&self) -> Digest32 {
        self.witness.channel_id
    }

    /// The newcomer's fingerprint.
    #[must_use]
    pub fn joiner(&self) -> Digest32 {
        self.witness.joiner_id
    }

    /// Frame for the wire (tag `0x0020`): `[key, witness body]`.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2)
            .bytes(&self.key.to_bytes())
            .bytes(&self.witness.body_bytes());
        frame(StructTag::AdmissionNotice, &e.finish())
    }

    /// Parse a framed notice, strictly. Checks that the key is the witnessed joiner's; does
    /// **not** verify the witness, which needs its signer's key: [`AdmissionNotice::verify`].
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::AdmissionNotice {
            return Err(Error::MalformedRendezvous(
                "admission notice wrong struct tag",
            ));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 2 {
            return Err(Error::MalformedRendezvous("admission notice arity"));
        }
        let key: [u8; COMPOSITE_PUB_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedRendezvous("admission notice key length"))?;
        let witness = JoinWitness::from_body(d.bytes()?)?;
        d.finish()?;
        Self::new(CompositePublicKey::from_bytes(&key)?, witness)
    }

    /// Verify the witness under `witness_key`, the key of a member the verifier already admits,
    /// for `channel_id` at `epoch`.
    pub fn verify(
        &self,
        witness_key: &CompositePublicKey,
        channel_id: &Digest32,
        epoch: u64,
    ) -> Result<()> {
        self.witness
            .verify(witness_key, channel_id, epoch, &self.key.fingerprint())
    }
}
