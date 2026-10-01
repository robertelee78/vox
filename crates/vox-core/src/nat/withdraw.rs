//! The **board withdraw** (tag `0x0018`, domain `vox/board-withdraw/v1`, V030-14): a signed
//! statement, put on a rendezvous board, that takes records off it at once.
//!
//! A leave or an end is a fact on the room's log (V030-08), and a member's node acts on it the
//! moment it holds it. A board holds no log: it kept the room's genesis for good and a member's
//! records until they lapsed (two hours for an address, seven days for a bundle), and peers that
//! still mirrored them put them back. The decider (2026-10-01): "leave and end remove the
//! member's and room's records from anchors at once".
//!
//! Two scopes:
//! - **self** — a member takes its own bundle and address records for the room off the board.
//!   Signed by that member; the board checks it against the key it holds for the member.
//! - **room** — the room's genesis and every record of the room come off the board. Signed by
//!   the room's creator, whose key is the genesis's own, or by an admin who carries the
//!   creator's admin certificate naming it, which the board checks against the genesis.
//!
//! The board keeps what it was told: a member's tombstone refuses its records stamped no later
//! than the withdraw (a member that joins again publishes newer ones, which are taken), and a
//! room's tombstone refuses everything of the room for good.
//!
//! **What a board cannot know:** it holds no log, so it cannot see an admin certificate revoked
//! after it was issued. An admin whose admin was taken back can still take a room off boards; it
//! cannot end the room for its members, which every member's node decides from the log.
//!
//! Body: `[channelID, epoch, author_id, scope, timestamp, admin_cert]`, `admin_cert` empty unless
//! a room withdraw is signed by an admin.

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::cert::AdminCert;
use crate::hash::{Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{frame, parse_frame, signing_input, StructTag};

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
    /// For a room withdraw signed by an admin: the creator's admin certificate naming it (wire
    /// form). Empty otherwise.
    pub admin_cert: Vec<u8>,
    /// The signer's composite root signature.
    pub signature: CompositeSignature,
}

fn body(
    channel_id: &Digest32,
    epoch: u64,
    author_id: &Digest32,
    scope: WithdrawScope,
    timestamp: u64,
    admin_cert: &[u8],
) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(6)
        .bytes(channel_id)
        .uint(epoch)
        .bytes(author_id)
        .uint(scope.code())
        .uint(timestamp)
        .bytes(admin_cert);
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
        admin_cert: Vec<u8>,
    ) -> Result<Self> {
        let author_id = signer.fingerprint();
        let input = signing_input(
            StructTag::BoardWithdraw,
            &body(channel_id, epoch, &author_id, scope, timestamp, &admin_cert),
        );
        let signature = signer.sign(&input)?;
        Ok(Self {
            channel_id: *channel_id,
            epoch,
            author_id,
            scope,
            timestamp,
            admin_cert,
            signature,
        })
    }

    fn signing_input(&self) -> Vec<u8> {
        signing_input(
            StructTag::BoardWithdraw,
            &body(
                &self.channel_id,
                self.epoch,
                &self.author_id,
                self.scope,
                self.timestamp,
                &self.admin_cert,
            ),
        )
    }

    /// Frame for the wire (tag `0x0018`): the body fields then the signature.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(7)
            .bytes(&self.channel_id)
            .uint(self.epoch)
            .bytes(&self.author_id)
            .uint(self.scope.code())
            .uint(self.timestamp)
            .bytes(&self.admin_cert)
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
        if d.array()? != 7 {
            return Err(Error::MalformedRendezvous("board withdraw arity"));
        }
        let digest = |d: &mut Decoder<'_>| -> Result<Digest32> {
            d.bytes()?
                .try_into()
                .map_err(|_| Error::MalformedRendezvous("board withdraw digest length"))
        };
        let channel_id = digest(&mut d)?;
        let epoch = d.uint()?;
        let author_id = digest(&mut d)?;
        let scope = WithdrawScope::from_code(d.uint()?)?;
        let timestamp = d.uint()?;
        let admin_cert = d.bytes()?.to_vec();
        let sig: [u8; COMPOSITE_SIG_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedRendezvous("board withdraw sig length"))?;
        d.finish()?;
        Ok(Self {
            channel_id,
            epoch,
            author_id,
            scope,
            timestamp,
            admin_cert,
            signature: CompositeSignature::from_bytes(&sig)?,
        })
    }

    /// Verify the signature under `signer_key`, and that it is the key of `author_id`.
    pub fn verify(&self, signer_key: &CompositePublicKey) -> Result<()> {
        if signer_key.fingerprint() != self.author_id {
            return Err(Error::MalformedRendezvous(
                "board withdraw author != signer fingerprint",
            ));
        }
        signer_key.verify(&self.signing_input(), &self.signature)
    }

    /// For a room withdraw signed by an admin: the key the creator's certificate names, once the
    /// certificate is checked against `creator` — signed by the creator, for this room, naming
    /// this signer, carrying `admin`. `None` if there is no certificate or it does not hold.
    #[must_use]
    pub fn admin_key(&self, creator: &CompositePublicKey) -> Option<CompositePublicKey> {
        if self.admin_cert.is_empty() {
            return None;
        }
        let cert = AdminCert::from_wire(&self.admin_cert).ok()?;
        cert.verify(creator).ok()?;
        let named = cert.body.delegate_pubkey.clone();
        let ok = cert.body.channel_id == self.channel_id
            && cert.body.issuer_id == creator.fingerprint()
            && named.fingerprint() == self.author_id
            && cert
                .body
                .capability_set
                .grants(&crate::governance::capability::Capability::Admin);
        ok.then_some(named)
    }
}
