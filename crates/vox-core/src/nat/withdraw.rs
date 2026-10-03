//! The **board withdraw** (tag `0x0019`, domain `vox/board-withdraw/v1`) and the **admin roster**
//! (tag `0x001A`, domain `vox/admin-roster/v1`), V030-14: signed statements, put on a rendezvous
//! board, that take records off it at once and say who may.
//!
//! A leave or an end is a fact on the room's log (V030-08), and a member's node acts on it the
//! moment it holds it. A board holds no log: it kept the room's genesis for good and a member's
//! records until they lapsed (two hours for an address, seven days for a bundle), and peers that
//! still mirrored them put them back. The decider (2026-10-01): "leave and end remove the
//! member's and room's records from anchors at once".
//!
//! A withdraw has two scopes:
//! - **self** — a member takes its own bundle and address records for the room off the board.
//!   Signed by that member; the board checks it against the key it holds for the member.
//! - **room** — the room's genesis and every record of the room come off the board. Signed by
//!   the room's creator, whose key is the genesis's own, or by a member the creator's **current**
//!   admin roster names.
//!
//! **The roster** is how a board, which holds no log, knows who is an admin now: the creator signs
//! the room's admins each time it adds or takes one back, and puts that on the boards. A board
//! keeps the newest roster of each room and honours a room withdraw only from the creator or a
//! member on it, so an admin whose admin was taken back is refused (the decider, 2026-10-01).
//!
//! The board keeps what it was told: a member's tombstone refuses its records stamped no later
//! than the withdraw (a member that joins again publishes newer ones, which are taken), and a
//! room's tombstone refuses everything of the room for good.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

/// The most admins a roster names: a room's members are bounded far below this.
pub const MAX_ROSTER: usize = 512;

/// What a withdraw takes off a board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawScope {
    /// The signer's own records for the room.
    Member,
    /// The whole room: its genesis and every record.
    Room,
}

impl WithdrawScope {
    fn code(self) -> u64 {
        match self {
            WithdrawScope::Member => 1,
            WithdrawScope::Room => 2,
        }
    }

    fn from_code(c: u64) -> Result<Self> {
        match c {
            1 => Ok(WithdrawScope::Member),
            2 => Ok(WithdrawScope::Room),
            _ => Err(Error::MalformedRendezvous("board withdraw scope")),
        }
    }
}

fn take_digest(d: &mut Decoder<'_>, what: &'static str) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedRendezvous(what))
}

fn take_sig(d: &mut Decoder<'_>, what: &'static str) -> Result<CompositeSignature> {
    let sig: [u8; COMPOSITE_SIG_LEN] = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedRendezvous(what))?;
    CompositeSignature::from_bytes(&sig)
}

/// A signed board withdraw.
#[derive(Debug, Clone)]
pub struct BoardWithdraw {
    /// The room.
    pub channel_id: Digest32,
    /// The epoch the signer's records are filed under.
    pub epoch: u64,
    /// The signer.
    pub author_id: Digest32,
    /// What it takes off.
    pub scope: WithdrawScope,
    /// When it was said, unix seconds.
    pub timestamp: u64,
    /// The signer's composite root signature.
    pub signature: CompositeSignature,
}

fn withdraw_body(
    channel_id: &Digest32,
    epoch: u64,
    author_id: &Digest32,
    scope: WithdrawScope,
    timestamp: u64,
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .bytes(channel_id)
        .uint(epoch)
        .bytes(author_id)
        .uint(scope.code())
        .uint(timestamp);
    e.finish()
}

impl BoardWithdraw {
    /// Build and root-sign a withdraw.
    pub fn build(
        signer: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        scope: WithdrawScope,
        timestamp: u64,
    ) -> Result<Self> {
        let author_id = signer.fingerprint();
        let input = signing_input(
            StructTag::BoardWithdraw,
            &withdraw_body(channel_id, epoch, &author_id, scope, timestamp),
        );
        let signature = signer.sign(&input)?;
        Ok(Self {
            channel_id: *channel_id,
            epoch,
            author_id,
            scope,
            timestamp,
            signature,
        })
    }

    /// Frame for the wire (tag `0x0019`): the body fields then the signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(6)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.author_id)
            .uint(self.scope.code())
            .uint(self.timestamp)
            .bytes(&self.signature.to_bytes());
        frame(StructTag::BoardWithdraw, &e.finish())
    }

    /// Parse a framed withdraw (does NOT verify).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::BoardWithdraw {
            return Err(Error::MalformedRendezvous(
                "board withdraw wrong struct tag",
            ));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 6 {
            return Err(Error::MalformedRendezvous("board withdraw arity"));
        }
        let channel_id = take_digest(&mut d, "board withdraw digest length")?;
        let epoch = d.uint()?;
        let author_id = take_digest(&mut d, "board withdraw digest length")?;
        let scope = WithdrawScope::from_code(d.uint()?)?;
        let timestamp = d.uint()?;
        let signature = take_sig(&mut d, "board withdraw sig length")?;
        d.finish()?;
        Ok(Self {
            channel_id,
            epoch,
            author_id,
            scope,
            timestamp,
            signature,
        })
    }

    /// Verify the signature under `signer_key`, and that it is the key of `author_id`.
    pub fn verify(&self, signer_key: &CompositePublicKey) -> Result<()> {
        if signer_key.fingerprint() != self.author_id {
            return Err(Error::MalformedRendezvous(
                "board withdraw author != signer fingerprint",
            ));
        }
        let input = signing_input(
            StructTag::BoardWithdraw,
            &withdraw_body(
                &self.channel_id,
                self.epoch,
                &self.author_id,
                self.scope,
                self.timestamp,
            ),
        );
        signer_key.verify(&input, &self.signature)
    }
}

/// A room's admins as its creator signed them: who a board takes a room withdraw from besides the
/// creator.
#[derive(Debug, Clone)]
pub struct AdminRoster {
    /// The room.
    pub channel_id: Digest32,
    /// When the creator signed it, unix milliseconds: the newest a board holds wins.
    pub timestamp_ms: u64,
    /// The admins, the creator not among them, in fingerprint order.
    pub admins: Vec<Digest32>,
    /// The creator's composite root signature.
    pub signature: CompositeSignature,
}

fn roster_body(channel_id: &Digest32, timestamp_ms: u64, admins: &[Digest32]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(3)
        .bytes(channel_id)
        .uint(timestamp_ms)
        .array(admins.len());
    for a in admins {
        e.bytes(a);
    }
    e.finish()
}

impl AdminRoster {
    /// Build and root-sign the room's roster (the creator only; the board checks).
    pub fn build(
        creator: &dyn RootSigner,
        channel_id: &Digest32,
        timestamp_ms: u64,
        mut admins: Vec<Digest32>,
    ) -> Result<Self> {
        admins.sort_unstable();
        admins.dedup();
        if admins.len() > MAX_ROSTER {
            return Err(Error::SizeLimitExceeded("admin roster"));
        }
        let input = signing_input(
            StructTag::AdminRoster,
            &roster_body(channel_id, timestamp_ms, &admins),
        );
        let signature = creator.sign(&input)?;
        Ok(Self {
            channel_id: *channel_id,
            timestamp_ms,
            admins,
            signature,
        })
    }

    /// Frame for the wire (tag `0x001A`): the body fields then the signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .bytes(&self.channel_id)
            .uint(self.timestamp_ms)
            .array(self.admins.len());
        for a in &self.admins {
            e.bytes(a);
        }
        e.bytes(&self.signature.to_bytes());
        frame(StructTag::AdminRoster, &e.finish())
    }

    /// Parse a framed roster (does NOT verify).
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::AdminRoster {
            return Err(Error::MalformedRendezvous("admin roster wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 4 {
            return Err(Error::MalformedRendezvous("admin roster arity"));
        }
        let channel_id = take_digest(&mut d, "admin roster digest length")?;
        let timestamp_ms = d.uint()?;
        let n = d.array()?;
        if n > MAX_ROSTER {
            return Err(Error::SizeLimitExceeded("admin roster"));
        }
        let mut admins = Vec::with_capacity(n);
        for _ in 0..n {
            admins.push(take_digest(&mut d, "admin roster digest length")?);
        }
        let signature = take_sig(&mut d, "admin roster sig length")?;
        d.finish()?;
        Ok(Self {
            channel_id,
            timestamp_ms,
            admins,
            signature,
        })
    }

    /// Verify it is signed by `creator`.
    pub fn verify(&self, creator: &CompositePublicKey) -> Result<()> {
        let input = signing_input(
            StructTag::AdminRoster,
            &roster_body(&self.channel_id, self.timestamp_ms, &self.admins),
        );
        creator.verify(&input, &self.signature)
    }
}
