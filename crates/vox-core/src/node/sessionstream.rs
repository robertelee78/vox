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
use crate::node::history_budget::{BufferCharge, Job};
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::VoxConnection;
use crate::transport::streams::{open_typed, StreamKind};

const DOMAIN: &[u8] = b"vox/private-session/v1";
pub(crate) const MAX_RECORD: usize = 96 * 1024;
pub(crate) const PAGE_RECORDS: usize = 32;
pub(crate) const MAX_PAGE: usize = 1024 * 1024;
/// Outer framing/cursor overhead; each record additionally has at most five CBOR length bytes.
pub(crate) const PAGE_OVERHEAD: usize = 4096;
/// Wire, decoder copies, one parsed record and encoder/sealing scratch remain charged together.
pub(crate) const PAGE_ENVELOPE: usize = 4 * MAX_PAGE;
/// A current private pull must retain its page while applying it under a second room/store
/// working envelope. Admit both halves together so a set of received pages cannot fill the
/// shared foreground reservation and then all fail to acquire the work needed to finish.
pub(crate) const CURRENT_PAGE_ENVELOPE: usize = 2 * PAGE_ENVELOPE;

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

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub(crate) struct Cursor {
    pub incarnation: Digest32,
    pub after: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Locator {
    pub id: u64,
    pub hash: Digest32,
}

/// Current delivery never authorizes older private history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Query {
    LiveTail,
    ArchiveInventory {
        lo: u64,
        hi: u64,
        before: u64,
    },
    ArchiveRecords {
        lo: u64,
        hi: u64,
        positions: Vec<Locator>,
    },
}
impl Query {
    pub(crate) fn archive(&self) -> bool {
        !matches!(self, Self::LiveTail)
    }
    fn validate(&self) -> Result<()> {
        let interval = |lo: u64, hi: u64| {
            if lo == 0 || lo > hi || hi - lo >= PAGE_RECORDS as u64 {
                Err(Error::MalformedBundle("private history interval"))
            } else {
                Ok(())
            }
        };
        match self {
            Self::LiveTail => Ok(()),
            Self::ArchiveInventory { lo, hi, before } => {
                interval(*lo, *hi)?;
                if *before
                    != hi
                        .checked_add(1)
                        .ok_or(Error::MalformedBundle("private history bound"))?
                {
                    return Err(Error::MalformedBundle("private history inventory boundary"));
                }
                Ok(())
            }
            Self::ArchiveRecords { lo, hi, positions } => {
                interval(*lo, *hi)?;
                if positions.is_empty()
                    || positions.len() > PAGE_RECORDS
                    || positions.iter().any(|p| p.id < *lo || p.id > *hi)
                    || positions.windows(2).any(|p| p[0].id >= p[1].id)
                {
                    return Err(Error::MalformedBundle("private history exact selection"));
                }
                Ok(())
            }
        }
    }
    fn put(&self, e: &mut Encoder) {
        match self {
            Self::LiveTail => {
                e.array(1).uint(0);
            }
            Self::ArchiveInventory { lo, hi, before } => {
                e.array(4).uint(2).uint(*lo).uint(*hi).uint(*before);
            }
            Self::ArchiveRecords { lo, hi, positions } => {
                e.array(4).uint(3).uint(*lo).uint(*hi);
                put_locators(e, positions);
            }
        }
    }
    fn read(d: &mut Decoder<'_>) -> Result<Self> {
        let query = match (d.array()?, d.uint()?) {
            (1, 0) => Self::LiveTail,
            (4, 2) => Self::ArchiveInventory {
                lo: d.uint()?,
                hi: d.uint()?,
                before: d.uint()?,
            },
            (4, 3) => Self::ArchiveRecords {
                lo: d.uint()?,
                hi: d.uint()?,
                positions: read_locators(d)?,
            },
            _ => return Err(Error::MalformedBundle("private Session purpose")),
        };
        query.validate()?;
        Ok(query)
    }
}

pub(crate) struct Ask {
    /// Local grant revision; never sent to another node.
    pub revision: u64,
    pub room: Digest32,
    pub epoch: u64,
    pub cursor: Cursor,
    pub query: Query,
}

pub(crate) struct Page {
    /// The initiating node's grant revision and query are local, never accepted from the peer.
    pub revision: u64,
    pub query: Query,
    pub cursor: Cursor,
    pub more: bool,
    pub records: Vec<Vec<u8>>,
    pub positions: Vec<u64>,
    pub hints: Vec<Locator>,
    /// Keeps the daemon-wide reservation alive through durable application.
    pub charge: BufferCharge,
}

fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?
        .try_into()
        .map_err(|_| Error::MalformedBundle("private Session digest"))
}
fn put_locators(e: &mut Encoder, positions: &[Locator]) {
    e.array(positions.len());
    for position in positions {
        e.array(2).uint(position.id).bytes(&position.hash);
    }
}
fn read_locators(d: &mut Decoder<'_>) -> Result<Vec<Locator>> {
    let count = d.array()?;
    if count > PAGE_RECORDS {
        return Err(Error::SizeLimitExceeded("private history inventory"));
    }
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        if d.array()? != 2 {
            return Err(Error::MalformedBundle("private history locator"));
        }
        result.push(Locator {
            id: d.uint()?,
            hash: digest(d)?,
        });
    }
    Ok(result)
}

impl Ask {
    fn wire(&self) -> Result<Vec<u8>> {
        self.query.validate()?;
        let mut e = Encoder::new();
        e.array(6)
            .uint(2)
            .bytes(&self.room)
            .uint(self.epoch)
            .bytes(&self.cursor.incarnation)
            .uint(self.cursor.after);
        self.query.put(&mut e);
        Ok(e.finish())
    }
}

pub(crate) async fn read_ask(recv: &mut RecvStream) -> Result<Ask> {
    let bytes = read_frame(recv, 4096)
        .await?
        .ok_or(Error::MalformedBundle("private Session ask missing"))?;
    let mut d = Decoder::new(&bytes);
    if d.array()? != 6 || d.uint()? != 2 {
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
        query: Query::read(&mut d)?,
    };
    d.finish()?;
    Ok(ask)
}

pub(crate) async fn answer(mut send: SendStream, page: Page) -> Result<()> {
    if page.records.len() > PAGE_RECORDS
        || page.records.len() != page.positions.len()
        || page.hints.len() > PAGE_RECORDS
    {
        return Err(Error::SizeLimitExceeded("private Session page records"));
    }
    let _charge = page.charge;
    let mut e = Encoder::new();
    e.array(6)
        .uint(2)
        .bytes(&page.cursor.incarnation)
        .uint(page.cursor.after)
        .uint(u64::from(page.more))
        .array(page.records.len());
    for (id, record) in page.positions.into_iter().zip(page.records) {
        if record.len() > MAX_RECORD {
            return Err(Error::SizeLimitExceeded("private Session record"));
        }
        e.array(2).uint(id).bytes(&record);
    }
    put_locators(&mut e, &page.hints);
    let wire = e.finish();
    if wire.len() + 4 > MAX_PAGE {
        return Err(Error::SizeLimitExceeded("private Session page"));
    }
    write_frame(&mut send, &wire).await?;
    send.finish()
        .map_err(|_| Error::Unreachable("private Session answer closed"))
}

pub(crate) async fn pull(conn: &VoxConnection, ask: Ask, job: Job) -> Result<Page> {
    let charge = job
        .reserve(PAGE_ENVELOPE)
        .ok_or(Error::StreamRefused("private Session transfer busy"))?;
    pull_precharged(conn, ask, charge).await
}

/// Pull one page using capacity the current-delivery owner admitted together with its later
/// room/store application work. Explicit history keeps using [`pull`]'s independent envelope.
pub(crate) async fn pull_precharged(
    conn: &VoxConnection,
    ask: Ask,
    charge: BufferCharge,
) -> Result<Page> {
    let (mut send, mut recv) = open_typed(conn, StreamKind::Session).await?;
    write_frame(&mut send, &ask.wire()?).await?;
    send.finish()
        .map_err(|_| Error::Unreachable("private Session request closed"))?;
    let bytes = read_frame(&mut recv, MAX_PAGE - 4)
        .await?
        .ok_or(Error::MalformedBundle("private Session answer missing"))?;
    let mut d = Decoder::new(&bytes);
    if d.array()? != 6 || d.uint()? != 2 {
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
    let mut positions = Vec::with_capacity(count);
    for _ in 0..count {
        if d.array()? != 2 {
            return Err(Error::MalformedBundle("private Session record locator"));
        }
        positions.push(d.uint()?);
        let record = d.bytes()?;
        if record.len() > MAX_RECORD {
            return Err(Error::SizeLimitExceeded("private Session record"));
        }
        records.push(record.to_vec());
    }
    let hints = read_locators(&mut d)?;
    d.finish()?;
    if ask.query.archive() && cursor.incarnation != ask.cursor.incarnation {
        return Err(Error::MalformedBundle("private history donor changed"));
    }
    match &ask.query {
        Query::LiveTail => {
            if !hints.is_empty()
                || (cursor.incarnation == ask.cursor.incarnation && cursor.after < ask.cursor.after)
                || positions.iter().any(|id| {
                    *id == 0 || *id > cursor.after || cursor.after - *id >= PAGE_RECORDS as u64
                })
                || positions.windows(2).any(|p| p[0] >= p[1])
            {
                return Err(Error::MalformedBundle("private live tail binding"));
            }
        }
        Query::ArchiveInventory { lo, hi, before } => {
            if !records.is_empty()
                || cursor.after < *lo
                || cursor.after > *before
                || hints
                    .iter()
                    .any(|p| p.id < *lo || p.id > *hi || p.id >= *before)
                || hints.windows(2).any(|p| p[0].id >= p[1].id)
            {
                return Err(Error::MalformedBundle("private history inventory binding"));
            }
        }
        Query::ArchiveRecords {
            positions: wanted, ..
        } => {
            if !hints.is_empty()
                || records.is_empty()
                || records.len() > wanted.len()
                || more != (records.len() < wanted.len())
                || positions.last().copied() != Some(cursor.after)
                || positions
                    .iter()
                    .zip(&records)
                    .zip(wanted)
                    .any(|((id, wire), want)| {
                        *id != want.id || Record::read(wire).map_or(true, |r| r.hash() != want.hash)
                    })
            {
                return Err(Error::MalformedBundle("private history body selection"));
            }
        }
    }
    Ok(Page {
        revision: ask.revision,
        query: ask.query,
        cursor,
        more,
        records,
        positions,
        hints,
        charge,
    })
}
