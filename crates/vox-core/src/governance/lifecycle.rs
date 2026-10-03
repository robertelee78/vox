//! The **room lifecycle** facts (tag `0x0019`, domain `vox/room-lifecycle/v1`): the creator, or
//! an admin it named, ending the room for everyone, and the creator's chosen idle end (V030-08).
//!
//! ## Why these are log facts
//! Membership in ADR-007 is emergent: every node admits authors from what it witnessed and
//! keeps them. So "this room is over" can only reach the other nodes the way every other fact
//! does: signed and on the log, where each node checks it itself and no peer can forge or
//! suppress one it already holds. A member leaving is its own presence statement
//! ([`crate::governance::presence`]), not a lifecycle fact.
//!
//! - **End** is signed by the room's creator (its genesis root admin) or an admin the creator
//!   delegated (the decider, 2026-10-01). Once a node holds it, the room takes no new message,
//!   and each member's node deletes it once it has passed the end on (the decider, 2026-10-03).
//! - **Idle end** is signed by the creator when the room is made. The room then ends once it
//!   has seen no message for the chosen number of seconds. A room whose creator did not
//!   choose one never ends by itself.
//!
//! Neither is bound to an epoch's lifetime. The `epoch` field records when it was said.
//!
//! Body: `[kind, channelID, epoch, issuer_id, idle_secs]`, `idle_secs` 0 unless the kind is
//! idle end. Kind codes 1 and 4 (a leave and a return, before the decider's 2026-10-03 ruling)
//! are reserved and refused.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// Which lifecycle fact an entry states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleKind {
    /// The room's creator has ended the room for everyone.
    End,
    /// The room's creator chose that the room end after this many seconds with no message.
    IdleEnd(u64),
}

impl LifecycleKind {
    fn code(self) -> u64 {
        match self {
            LifecycleKind::End => 2,
            LifecycleKind::IdleEnd(_) => 3,
        }
    }

    fn idle_secs(self) -> u64 {
        match self {
            LifecycleKind::IdleEnd(s) => s,
            _ => 0,
        }
    }

    fn from_parts(code: u64, idle_secs: u64) -> Result<Self> {
        match (code, idle_secs) {
            (2, 0) => Ok(LifecycleKind::End),
            (3, s) if s > 0 => Ok(LifecycleKind::IdleEnd(s)),
            _ => Err(Error::MalformedGovernance("room-lifecycle kind")),
        }
    }
}

/// The unsigned room-lifecycle body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomLifecycleBody {
    /// Which fact this states.
    pub kind: LifecycleKind,
    /// The channel this fact is about.
    pub channel_id: Digest32,
    /// The membership epoch in force when it was said.
    pub epoch: u64,
    /// The signer: the creator, or an admin it named.
    pub issuer_id: Digest32,
}

impl RoomLifecycleBody {
    /// Canonical-CBOR body `[kind, channelID, epoch, issuer_id, idle_secs]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .uint(self.kind.code())
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.issuer_id)
            .uint(self.kind.idle_secs());
        e.finish()
    }

    /// The signing input: `vox/room-lifecycle/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::RoomLifecycle, &self.canonical_body())
    }
}

/// A complete, root-signed room-lifecycle fact.
#[derive(Debug, Clone)]
pub struct RoomLifecycle {
    /// The signed body.
    pub body: RoomLifecycleBody,
    /// The issuer's composite root signature.
    pub signature: CompositeSignature,
}

impl RoomLifecycle {
    /// Build and root-sign a lifecycle fact.
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        kind: LifecycleKind,
    ) -> Result<Self> {
        if kind == LifecycleKind::IdleEnd(0) {
            return Err(Error::MalformedGovernance("room-lifecycle idle end of 0s"));
        }
        let body = RoomLifecycleBody {
            kind,
            channel_id: *channel_id,
            epoch,
            issuer_id: issuer_root.fingerprint(),
        };
        let signature = issuer_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x0019`): body fields then the signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let b = &self.body;
        let mut e = Encoder::new();
        e.array(6)
            .uint(b.kind.code())
            .bytes(&b.channel_id)
            .uint(b.epoch)
            .bytes(&b.issuer_id)
            .uint(b.kind.idle_secs())
            .bytes(&self.signature.to_bytes());
        frame(StructTag::RoomLifecycle, &e.finish())
    }

    /// Parse a framed lifecycle fact (does NOT verify).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::RoomLifecycle {
            return Err(Error::MalformedGovernance(
                "room-lifecycle wrong struct tag",
            ));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 6 {
            return Err(Error::MalformedGovernance("room-lifecycle wire arity"));
        }
        let code = d.uint()?;
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let issuer_id = take_digest(&mut d)?;
        let idle_secs = d.uint()?;
        let sig_bytes = d.bytes()?.to_vec();
        d.finish()?;
        let kind = LifecycleKind::from_parts(code, idle_secs)?;
        let sig: [u8; COMPOSITE_SIG_LEN] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedGovernance("room-lifecycle sig length"))?;
        let signature = CompositeSignature::from_bytes(&sig)?;
        Ok(Self {
            body: RoomLifecycleBody {
                kind,
                channel_id,
                epoch,
                issuer_id,
            },
            signature,
        })
    }

    /// Verify the issuer's signature and the `issuer_id`↔signer binding. Whether the issuer
    /// may state this fact (the creator, or an admin ending) is the evaluator's job.
    pub fn verify(&self, issuer_root: &CompositePublicKey) -> Result<()> {
        if issuer_root.fingerprint() != self.body.issuer_id {
            return Err(Error::MalformedGovernance(
                "room-lifecycle issuer_id != signer fingerprint",
            ));
        }
        issuer_root.verify(&self.body.signing_input(), &self.signature)
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("room-lifecycle digest length"))
}
