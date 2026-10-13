//! Private Session records, independent of the room DAG (ADR-031 SA-7).
//!
//! A record is root-signed as well as sealed by the drive chain. The outer signature permits
//! verification after a one-use decryption key has been consumed; it never grants permission.
//! Stream 13 is negotiated before any record bytes, so older peers refuse it without seeing an
//! unfamiliar room-log entry. Pages are bounded; the store's incarnation makes cursors safe
//! across reopen, retention and replay. Every page is authorized again by the serving node.

use quinn::{RecvStream, SendStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::group::message::GroupMessage;
use crate::hash::{sha256, Digest32, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::log::entry::Entry;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::VoxConnection;
use crate::transport::streams::{open_typed, StreamKind};

const DOMAIN: &[u8] = b"vox/private-session/v1";
pub(crate) const MAX_RECORD: usize = 96 * 1024;
pub(crate) const PAGE_RECORDS: usize = 32;
const MAX_PAGE: usize = PAGE_RECORDS * (MAX_RECORD + 8) + 128;

pub(crate) struct Record {
    pub room: Digest32,
    pub message: GroupMessage,
    proof: Proof,
}

enum Proof {
    Private(Box<CompositeSignature>),
    /// Preserve the original author's signature and entry identity during upgrade.
    Legacy(Box<Entry>),
}

impl Record {
    fn signing_input(room: &Digest32, message: &GroupMessage) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2).bytes(room).bytes(&message.to_wire());
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(e.finish());
        bytes
    }

    pub fn new(signer: &dyn RootSigner, room: Digest32, message: GroupMessage) -> Result<Self> {
        if message.header.author_id != signer.fingerprint()
            || message.header.channel_id != crate::node::drive::drive_channel(&room)
        {
            return Err(Error::MalformedBundle("private Session binding"));
        }
        let signature = signer.sign(&Self::signing_input(&room, &message))?;
        Ok(Self {
            room,
            message,
            proof: Proof::Private(Box::new(signature)),
        })
    }

    pub fn legacy(entry: Entry) -> Result<Self> {
        let message = GroupMessage::from_wire(
            entry
                .payload
                .as_deref()
                .ok_or(Error::MalformedBundle("legacy Session body missing"))?,
        )?;
        Ok(Self {
            room: entry.skeleton.channel_id,
            message,
            proof: Proof::Legacy(Box::new(entry)),
        })
    }

    pub fn wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match &self.proof {
            Proof::Private(signature) => {
                e.array(4)
                    .uint(1)
                    .bytes(&self.room)
                    .bytes(&self.message.to_wire())
                    .bytes(&signature.to_bytes());
            }
            Proof::Legacy(entry) => {
                e.array(2).uint(2).bytes(&entry.to_wire());
            }
        }
        e.finish()
    }

    pub fn read(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD {
            return Err(Error::SizeLimitExceeded("private Session record"));
        }
        let mut d = Decoder::new(bytes);
        let record = match (d.array()?, d.uint()?) {
            (4, 1) => {
                let room = digest(&mut d)?;
                let message = GroupMessage::from_wire(d.bytes()?)?;
                let signature: [u8; COMPOSITE_SIG_LEN] = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::InvalidSignatureEncoding)?;
                Self {
                    room,
                    message,
                    proof: Proof::Private(Box::new(CompositeSignature::from_bytes(&signature)?)),
                }
            }
            (2, 2) => Self::legacy(Entry::from_wire(d.bytes()?)?)?,
            _ => return Err(Error::MalformedBundle("private Session record version")),
        };
        d.finish()?;
        if record.wire() != bytes {
            return Err(Error::MalformedBundle(
                "noncanonical private Session record",
            ));
        }
        Ok(record)
    }

    pub fn verify(&self, room: &Digest32, key: &CompositePublicKey) -> Result<()> {
        if &self.room != room
            || self.message.header.author_id != key.fingerprint()
            || self.message.header.channel_id != crate::node::drive::drive_channel(room)
        {
            return Err(Error::MalformedBundle("private Session binding"));
        }
        match &self.proof {
            Proof::Private(signature) => {
                key.verify(&Self::signing_input(room, &self.message), signature)
            }
            Proof::Legacy(entry) => {
                if entry.skeleton.author_id != self.message.header.author_id
                    || entry.skeleton.epoch != self.message.header.epoch
                {
                    return Err(Error::MalformedBundle("legacy Session binding"));
                }
                entry.verify(key)
            }
        }
    }

    pub fn hash(&self) -> Digest32 {
        match &self.proof {
            Proof::Private(_) => sha256(&self.wire()),
            Proof::Legacy(entry) => entry.entry_hash(),
        }
    }

    pub fn legacy_claimed_ms(&self) -> Option<u64> {
        match &self.proof {
            Proof::Legacy(entry) => Some(entry.skeleton.claimed_ms),
            Proof::Private(_) => None,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct Cursor {
    pub incarnation: Digest32,
    pub after: u64,
}

pub(crate) struct Ask {
    /// Local grant revision; never sent to another node.
    pub revision: u64,
    pub room: Digest32,
    pub epoch: u64,
    pub cursor: Cursor,
}

pub(crate) struct Page {
    /// The initiating node's grant revision; never read from the peer's frame.
    pub revision: u64,
    pub cursor: Cursor,
    pub more: bool,
    pub records: Vec<Vec<u8>>,
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("private Session digest"))
}

impl Ask {
    fn wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(5)
            .uint(1)
            .bytes(&self.room)
            .uint(self.epoch)
            .bytes(&self.cursor.incarnation)
            .uint(self.cursor.after);
        e.finish()
    }
}

pub(crate) async fn read_ask(recv: &mut RecvStream) -> Result<Ask> {
    let bytes = read_frame(recv, 128)
        .await?
        .ok_or(Error::MalformedBundle("private Session ask missing"))?;
    let mut d = Decoder::new(&bytes);
    if d.array()? != 5 || d.uint()? != 1 {
        return Err(Error::MalformedBundle("private Session ask version"));
    }
    let ask = Ask {
        revision: 0,
        room: digest(&mut d)?,
        epoch: d.uint()?,
        cursor: Cursor {
            incarnation: digest(&mut d)?,
            after: d.uint()?,
        },
    };
    d.finish()?;
    Ok(ask)
}

pub(crate) async fn answer(mut send: SendStream, page: Page) -> Result<()> {
    let mut e = Encoder::new();
    e.array(5)
        .uint(1)
        .bytes(&page.cursor.incarnation)
        .uint(page.cursor.after)
        .uint(u64::from(page.more))
        .array(page.records.len());
    for record in page.records {
        e.bytes(&record);
    }
    write_frame(&mut send, &e.finish()).await?;
    send.finish()
        .map_err(|_| Error::Unreachable("private Session answer closed"))
}

pub(crate) async fn pull(conn: &VoxConnection, ask: Ask) -> Result<Page> {
    let (mut send, mut recv) = open_typed(conn, StreamKind::Session).await?;
    write_frame(&mut send, &ask.wire()).await?;
    send.finish()
        .map_err(|_| Error::Unreachable("private Session request closed"))?;
    let bytes = read_frame(&mut recv, MAX_PAGE)
        .await?
        .ok_or(Error::MalformedBundle("private Session answer missing"))?;
    let mut d = Decoder::new(&bytes);
    if d.array()? != 5 || d.uint()? != 1 {
        return Err(Error::MalformedBundle("private Session answer version"));
    }
    let cursor = Cursor {
        incarnation: digest(&mut d)?,
        after: d.uint()?,
    };
    let more = match d.uint()? {
        0 => false,
        1 => true,
        _ => return Err(Error::MalformedBundle("private Session continuation")),
    };
    let count = d.array()?;
    if count > PAGE_RECORDS {
        return Err(Error::SizeLimitExceeded("private Session page"));
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let record = d.bytes()?;
        if record.len() > MAX_RECORD {
            return Err(Error::SizeLimitExceeded("private Session record"));
        }
        records.push(record.to_vec());
    }
    d.finish()?;
    if cursor.incarnation == ask.cursor.incarnation && cursor.after < ask.cursor.after {
        return Err(Error::MalformedBundle("private Session cursor regressed"));
    }
    Ok(Page {
        revision: ask.revision,
        cursor,
        more,
        records,
    })
}
