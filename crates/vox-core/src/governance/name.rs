//! The **room name** (tag `0x001F`, domain `vox/room-name/v1`): the room's one shared name,
//! stated by its creator or an admin (ADR-028 R-1).
//!
//! Every member sees the room under the same name, because the name is a signed fact on the
//! room's log, not a label each member picks. It is set when the room is made and changed only
//! by the creator or an admin it named (the `policy` capability, ADR-007 G-5). The causally last
//! statement by an admin wins, as retention does (ADR-023 RL-2.1); the evaluator folds them.
//!
//! The name is one DNS label (ADR-028 R-2), because it is the room part of the readable form of
//! every service address.
//!
//! Body: `[channelID, epoch, issuer_id, name]`.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// The longest room name: one DNS label.
pub const MAX_ROOM_NAME: usize = 63;

/// `name` as a room name: folded to lower case, and refused with the reason unless it is one DNS
/// label (ADR-028 R-2).
///
/// # Errors
/// A sentence for the person who typed it, saying what is wrong with it.
pub fn room_name(name: &str) -> std::result::Result<String, String> {
    let folded = name.trim().to_ascii_lowercase();
    if folded.is_empty() {
        return Err("a room name cannot be empty".to_owned());
    }
    if folded.len() > MAX_ROOM_NAME {
        return Err(format!(
            "a room name is at most {MAX_ROOM_NAME} characters; `{name}` has {}",
            folded.len()
        ));
    }
    if let Some(c) = folded
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
    {
        return Err(format!(
            "a room name holds only letters a-z, digits and `-` (it is part of every service \
             address); `{name}` has {c:?}"
        ));
    }
    if folded.starts_with('-') || folded.ends_with('-') {
        return Err(format!(
            "a room name cannot start or end with `-`; `{name}` does"
        ));
    }
    Ok(folded)
}

fn check_name(name: &str) -> Result<()> {
    match room_name(name) {
        Ok(folded) if folded == name => Ok(()),
        _ => Err(Error::MalformedGovernance("room name is not a DNS label")),
    }
}

/// The unsigned room-name body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomNameBody {
    /// The room.
    pub channel_id: Digest32,
    /// The membership epoch the statement is made in.
    pub epoch: u64,
    /// The signer: the creator, or an admin it named.
    pub issuer_id: Digest32,
    /// The name: one lower-case DNS label.
    pub name: String,
}

impl RoomNameBody {
    /// Canonical-CBOR body `[channelID, epoch, issuer_id, name]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.issuer_id)
            .text(&self.name);
        e.finish()
    }

    /// The signing input: `vox/room-name/v1 ‖ canonical_body` (ADR-008).
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(StructTag::RoomName, &self.canonical_body())
    }
}

/// A complete, root-signed room-name statement.
#[derive(Debug, Clone)]
pub struct RoomName {
    /// The signed body.
    pub body: RoomNameBody,
    /// The issuer's composite root signature.
    pub signature: CompositeSignature,
}

impl RoomName {
    /// Build and root-sign `issuer_root`'s statement that `channel_id` is called `name`, which
    /// must already be a lower-case DNS label ([`room_name`]).
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        name: &str,
    ) -> Result<Self> {
        check_name(name)?;
        let body = RoomNameBody {
            channel_id: *channel_id,
            epoch,
            issuer_id: issuer_root.fingerprint(),
            name: name.to_owned(),
        };
        let signature = issuer_root.sign(&body.signing_input())?;
        Ok(Self { body, signature })
    }

    /// Frame for the wire/storage (tag `0x001F`): body fields then the signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let b = &self.body;
        let mut e = Encoder::new();
        e.array(5)
            .bytes(&b.channel_id)
            .uint(b.epoch)
            .bytes(&b.issuer_id)
            .text(&b.name)
            .bytes(&self.signature.to_bytes());
        frame(StructTag::RoomName, &e.finish())
    }

    /// Parse a framed room-name statement (does NOT verify).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::RoomName {
            return Err(Error::MalformedGovernance("room name wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 5 {
            return Err(Error::MalformedGovernance("room name wire arity"));
        }
        let channel_id = take_digest(&mut d)?;
        let epoch = d.uint()?;
        let issuer_id = take_digest(&mut d)?;
        let name = d.text()?.to_owned();
        check_name(&name)?;
        let sig: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedGovernance("room name sig length"))?;
        d.finish()?;
        Ok(Self {
            body: RoomNameBody {
                channel_id,
                epoch,
                issuer_id,
                name,
            },
            signature: CompositeSignature::from_bytes(&sig)?,
        })
    }

    /// Verify the signature and that `issuer_id` is the signer (structural; whether the issuer
    /// holds the `policy` capability is the evaluator's job).
    pub fn verify(&self, issuer_root: &CompositePublicKey) -> Result<()> {
        if issuer_root.fingerprint() != self.body.issuer_id {
            return Err(Error::MalformedGovernance(
                "room name issuer_id != signer fingerprint",
            ));
        }
        issuer_root.verify(&self.body.signing_input(), &self.signature)
    }
}

fn take_digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("room name digest length"))
}
