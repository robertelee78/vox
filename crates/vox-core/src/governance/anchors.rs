//! A room's complete anchor set, signed by its creator or an admin (ADR-032 AN-5).
//! Authorization and last-canonical-statement selection use the ordinary governance evaluator.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::nat::bootstrap::BootstrapSet;
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// The unsigned room-anchor body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomAnchorsBody {
    /// The room.
    pub channel_id: Digest32,
    /// The membership epoch the statement is made in.
    pub epoch: u64,
    /// The signer: the creator, or an admin it named.
    pub issuer_id: Digest32,
    /// The complete set; an empty signed set explicitly clears room anchors.
    pub anchors: BootstrapSet,
}

impl RoomAnchorsBody {
    /// Canonical-CBOR body `[channelID, epoch, issuer_id, anchors]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.issuer_id)
            .bytes(&self.anchors.to_bytes());
        e.finish()
    }

    /// The signing input: `vox/room-anchors/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::RoomAnchors, &self.canonical_body())
    }
}

/// A complete, root-signed room-anchor statement.
#[derive(Debug, Clone)]
pub struct RoomAnchors {
    /// The signed body.
    pub body: RoomAnchorsBody,
    /// The issuer's composite root signature.
    pub signature: CompositeSignature,
}

impl RoomAnchors {
    /// Build and root-sign a complete, bounded anchor-set statement.
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        anchors: &BootstrapSet,
    ) -> Result<Self> {
        let body = RoomAnchorsBody {
            channel_id: *channel_id,
            epoch,
            issuer_id: issuer_root.fingerprint(),
            anchors: anchors.clone(),
        };
        let signature = issuer_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x0021`): body fields then the signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let b = &self.body;
        let mut e = Encoder::new();
        e.array(5)
            .bytes(&b.channel_id)
            .uint(b.epoch)
            .bytes(&b.issuer_id)
            .bytes(&b.anchors.to_bytes())
            .bytes(&self.signature.to_bytes());
        frame(StructTag::RoomAnchors, &e.finish())
    }

    /// Parse a framed room-anchor statement (does NOT verify).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::RoomAnchors {
            return Err(Error::MalformedGovernance("room anchors wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 5 {
            return Err(Error::MalformedGovernance("room anchors wire arity"));
        }
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let issuer_id = take_digest(&mut d)?;
        let anchors = BootstrapSet::from_bytes(d.bytes()?)?;
        let sig: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedGovernance("room anchors sig length"))?;
        d.finish()?;
        Ok(Self {
            body: RoomAnchorsBody {
                channel_id,
                epoch,
                issuer_id,
                anchors,
            },
            signature: CompositeSignature::from_bytes(&sig)?,
        })
    }

    /// Verify the signature and that `issuer_id` is the signer (structural; whether the issuer
    /// holds the `policy` capability is the evaluator's job).
    pub fn verify(&self, issuer_root: &CompositePublicKey) -> Result<()> {
        if issuer_root.fingerprint() != self.body.issuer_id {
            return Err(Error::MalformedGovernance(
                "room anchors issuer_id != signer fingerprint",
            ));
        }
        issuer_root.verify(&self.body.signing_input(), &self.signature)
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("room anchors digest length"))
}
