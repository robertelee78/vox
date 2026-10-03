//! The **presence statement** (tag `0x0015`, domain `vox/presence/v1`): a member's own signed
//! word that it has left the room, or that it is back (V210-164).
//!
//! Membership is the log's: a key is in the room from its admission, and nothing ever took it
//! out, so a node that stopped holding a room stayed on every other member's roster for good.
//! A member that leaves ends its feed with `here = false`. Every member reads that the same way,
//! from the log, without needing anyone's sender key: a member whose feed ends in it has left.
//! Anything it authors later puts it back; a member that joins again says `here = true` once it
//! holds its own feed, so it is listed again before it says anything else.
//!
//! Only the member itself can make the statement: the body names its author, and the log entry
//! that carries it is signed by that author.
//!
//! It names the sender-key generation the member was sending under. A member that joins again
//! starts a new sender key, and the others hold the old one under its generation: a new key under
//! a number they already hold is one they keep refusing, so it never reads. The number in its last
//! statement is what it counts on from.
//!
//! Body: `{ channelID, epoch, author_id, here, chain_id }`.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// The unsigned presence body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceBody {
    /// The room.
    pub channel_id: Digest32,
    /// The membership epoch the statement is made in.
    pub epoch: u64,
    /// The member making it.
    pub author_id: Digest32,
    /// `false`: it has left. `true`: it is back.
    pub here: bool,
    /// The sender-key generation it sends under as it says so.
    pub chain_id: u64,
}

impl PresenceBody {
    /// Canonical-CBOR body `[channelID, epoch, author_id, here, chain_id]`, `here` as 0 or 1.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.author_id)
            .uint(u64::from(self.here))
            .uint(self.chain_id);
        e.finish()
    }

    /// The signing input: `vox/presence/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::Presence, &self.canonical_body())
    }
}

/// A complete, root-signed presence statement.
#[derive(Debug, Clone)]
pub struct Presence {
    /// The signed body.
    pub body: PresenceBody,
    /// The member's composite root signature.
    pub signature: CompositeSignature,
}

impl Presence {
    /// Build and root-sign `author_root`'s statement that it has left `channel_id` (`here` =
    /// false) or is back in it, sending under generation `chain_id`.
    pub fn build(
        author_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        here: bool,
        chain_id: u64,
    ) -> Result<Self> {
        let body = PresenceBody {
            channel_id: *channel_id,
            epoch,
            author_id: author_root.fingerprint(),
            here,
            chain_id,
        };
        let signature = author_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x0015`): body fields then the signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let b = &self.body;
        let mut e = Encoder::new();
        e.array(6)
            .bytes(&b.channel_id)
            .uint(b.epoch)
            .bytes(&b.author_id)
            .uint(u64::from(b.here))
            .uint(b.chain_id)
            .bytes(&self.signature.to_bytes());
        frame(StructTag::Presence, &e.finish())
    }

    /// Parse a framed presence statement (does NOT verify).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::Presence {
            return Err(Error::MalformedGovernance("presence wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 6 {
            return Err(Error::MalformedGovernance("presence wire arity"));
        }
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let author_id = take_digest(&mut d)?;
        let here = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedGovernance("presence here flag")),
        };
        let chain_id = d.uint()?;
        let sig: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedGovernance("presence sig length"))?;
        d.finish()?;
        Ok(Self {
            body: PresenceBody {
                channel_id,
                epoch,
                author_id,
                here,
                chain_id,
            },
            signature: CompositeSignature::from_bytes(&sig)?,
        })
    }

    /// Verify the signature and that `author_id` is the signer.
    pub fn verify(&self, author_root: &CompositePublicKey) -> Result<()> {
        if author_root.fingerprint() != self.body.author_id {
            return Err(Error::MalformedGovernance(
                "presence author_id != signer fingerprint",
            ));
        }
        author_root.verify(&self.body.signing_input(), &self.signature)
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("presence digest length"))
}
