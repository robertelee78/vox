//! Sealed control messages over a `pairwise` stream (ADR-016 §"Connections": the
//! stream kind that carries "SKDM and other sealed control messages").
//!
//! The only content today is the ADR-006 **sender-key distribution message**, the
//! thing that turns an admitted, consenting member into a *readable* one. It never
//! travels in the clear: the SKDM is sealed into the peer's ADR-004 pairwise session
//! (`Skdm::seal_into`), so the ratchet — not this module — provides
//! confidentiality, authenticity and forward secrecy. This module is the framing
//! and the ordering:
//!
//! | direction | frame |
//! |---|---|
//! | either | `SKDM` — the `channelID` plus one ratchet [`Message`] whose plaintext is an SKDM |
//!
//! The channelID travels **outside** the sealed message because the recipient needs
//! it to pick the session that decrypts it: an ADR-004 session is bound to a
//! `(channelID, epoch)`, a connection is per *peer*, and one peer may share several
//! channels with us. It is not a secret (it is on the board and in the invite link),
//! and the frame is inside the authenticated QUIC stream regardless.
//!
//! Both sides may send; a stream carries one frame per SKDM and the sender
//! half-closes when done, so delivering a key needs no round trip and cannot block
//! on the peer.
//!
//! ## Why the session, not the stream, is the trust boundary
//! A `pairwise` stream is only opened on a connection whose peer identity the
//! ADR-011 handshake proved, and [`crate::node::net::PeerPolicy`] admits the kind
//! only for a member. But neither fact is what makes an SKDM trustworthy: the SKDM
//! is root-signed by its author and verified against the author's admitted key by
//! [`crate::node::channel::ChannelState::accept_skdm`], and it arrives inside a
//! session bound to that identity's PQXDH handshake. A hostile relay can drop or
//! reorder these frames; it cannot forge, read or replay one into a different
//! channel or epoch.

use quinn::{RecvStream, SendStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::group::skdm::Skdm;
use crate::pairwise::init_message::InitialMessage;
use crate::pairwise::message::Message;
use crate::pairwise::session::Session;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::VoxConnection;
use crate::transport::streams::{open_typed, StreamKind};

/// The largest pairwise frame either side will read. An SKDM is a chain key plus a
/// composite signature and a signing key (~3.5 KiB); the ratchet header and AEAD
/// tag add little. 64 KiB leaves room for the later control messages this stream
/// kind is reserved for without being an allocation lever.
pub const MAX_PAIRWISE_FRAME: usize = 64 * 1024;

const OP_SKDM: u64 = 1;
/// The PQXDH opening a session that no join created. See [`PairwiseFrame::Hello`].
const OP_HELLO: u64 = 2;
/// `3` — an [`PairwiseFrame::Open`]: one ratchet message carrying nothing.
const OP_OPEN: u64 = 3;

/// One frame on a `pairwise` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairwiseFrame {
    /// A sealed sender-key distribution message: the wire bytes of one ratchet
    /// [`Message`] whose plaintext is an [`Skdm`].
    Skdm {
        /// The channel whose session seals this message.
        channel_id: crate::hash::Digest32,
        /// `Message::to_wire` bytes.
        sealed: Vec<u8>,
    },
    /// The ADR-004 [`crate::pairwise::init_message::InitialMessage`] that opens a
    /// session the join path never created.
    ///
    /// ADR-016 says members open sessions to one another **from their bundle
    /// records**, not only through a join. An initiator doing that has nowhere to put
    /// its PQXDH opening message: the join stream that normally carries one is not in
    /// play. So it rides here, as the first frame on the same stream that then carries
    /// the SKDM — one round of bytes, no extra stream, and the responder is holding the
    /// session by the time it reads the second frame.
    ///
    /// The responder authenticates it exactly as the join responder does: the message
    /// names a signed prekey and optionally a one-time prekey from that node's own
    /// ring, so a party with no prekey of ours cannot open a session at all, and a
    /// replayed one-time prekey is graded last-resort rather than silently accepted.
    Hello {
        /// The channel this session is bound to.
        channel_id: crate::hash::Digest32,
        /// `InitialMessage::to_wire` bytes.
        initial: Vec<u8>,
    },
    /// One ratchet message with an **empty** plaintext, whose only job is to open the
    /// responder's sending direction (M17.6).
    ///
    /// A PQXDH responder starts with no chains: `Ratchet::init_responder` says so in
    /// as many words — *"with no chains yet — they are established when the first
    /// inbound message triggers a DH ratchet step"*. The join's `InitialMessage`
    /// creates the session but delivers no ratchet message, so until the initiator
    /// sends one the responder cannot send at all.
    ///
    /// Joining used to satisfy that by releasing the joiner's **sender key** — which
    /// made a consent decision nobody took, to whichever member answered the join
    /// (M17.6, ADR-007 step 2 as revised). The session's need is real; meeting it with
    /// a grant was the defect. This frame meets it with nothing: it is a sealed message
    /// whose plaintext is empty, so the responder ratchets and gains a sending chain,
    /// and learns no key and receives no grant.
    Open {
        /// The channel this session is bound to.
        channel_id: crate::hash::Digest32,
        /// `Message::to_wire` bytes of a sealed, empty-plaintext ratchet message.
        sealed: Vec<u8>,
    },
}

impl PairwiseFrame {
    /// Canonical frame bytes: `[op, channel_id, payload]`.
    #[must_use]
    pub fn to_frame(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Self::Skdm { channel_id, sealed } => {
                e.array(3).uint(OP_SKDM).bytes(channel_id).bytes(sealed);
            }
            Self::Hello {
                channel_id,
                initial,
            } => {
                e.array(3).uint(OP_HELLO).bytes(channel_id).bytes(initial);
            }
            Self::Open { channel_id, sealed } => {
                e.array(3).uint(OP_OPEN).bytes(channel_id).bytes(sealed);
            }
        }
        e.finish()
    }

    /// Parse a pairwise frame.
    pub fn from_frame(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let n = d.array()?;
        let op = d.uint()?;
        let frame = match (op, n) {
            (OP_OPEN, 3) => Self::Open {
                channel_id: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("pairwise channel_id length"))?,
                sealed: d.bytes()?.to_vec(),
            },
            (OP_SKDM, 3) => Self::Skdm {
                channel_id: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("pairwise channel_id length"))?,
                sealed: d.bytes()?.to_vec(),
            },
            (OP_HELLO, 3) => Self::Hello {
                channel_id: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("pairwise channel_id length"))?,
                initial: d.bytes()?.to_vec(),
            },
            _ => return Err(Error::MalformedBundle("pairwise frame op")),
        };
        d.finish()?;
        Ok(frame)
    }
}

/// Seal `skdm` into `session` and write it as one frame for `channel_id`.
pub async fn send_skdm(
    send: &mut SendStream,
    channel_id: &crate::hash::Digest32,
    session: &mut Session,
    skdm: &Skdm,
) -> Result<()> {
    let sealed = skdm.seal_into(session)?.to_wire();
    let frame = PairwiseFrame::Skdm {
        channel_id: *channel_id,
        sealed,
    };
    write_frame(send, &frame.to_frame()).await
}

/// Open a `pairwise` stream on `conn`, deliver one SKDM, and half-close. The
/// stream's lifetime is the delivery: nothing is expected back.
///
/// `hello` is `Some` exactly when this node has just opened the session from the
/// peer's bundle record and the peer therefore does not hold it yet. It goes first,
/// on the same stream, so the peer has accepted the session before it reads the SKDM.
pub async fn deliver_skdm(
    conn: &VoxConnection,
    channel_id: &crate::hash::Digest32,
    session: &mut Session,
    skdm: &Skdm,
    hello: Option<&InitialMessage>,
) -> Result<quinn::SendStream> {
    let (mut send, _recv) = open_typed(conn, StreamKind::Pairwise).await?;
    if let Some(initial) = hello {
        let frame = PairwiseFrame::Hello {
            channel_id: *channel_id,
            initial: initial.to_wire(),
        };
        write_frame(&mut send, &frame.to_frame()).await?;
    }
    send_skdm(&mut send, channel_id, session, skdm).await?;
    let _ = send.finish();
    // Returned so the caller can learn whether the key was taken: see `refused`.
    Ok(send)
}

/// Whether the far side refused a delivered key: `Some(why)` if so, `None` if it took it.
///
/// **Written is not delivered.** A stream the recipient refuses at accept, or whose key it cannot
/// open, is stopped with a Vox wire code, and every Vox wire code is non-zero. A key that was
/// taken ends with the stream read to its end, or dropped once read, which is a stop with 0.
/// Anything else (the connection lost before an answer, or no answer at all within `patience`)
/// is counted as not delivered as well: sending a key twice is harmless, and never sending it
/// leaves a member unable to read. Awaited on its own task, never on the actor: the answer
/// comes after the recipient's actor has handled the key.
pub async fn refused(send: quinn::SendStream, patience: std::time::Duration) -> Option<String> {
    match tokio::time::timeout(patience, send.stopped()).await {
        Ok(Ok(None)) => None,
        Ok(Ok(Some(code))) if code.into_inner() == 0 => None,
        Ok(Ok(Some(code))) => Some(format!("stopped with code {}", code.into_inner())),
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some(format!("no answer within {}s", patience.as_secs())),
    }
}

/// Open a `pairwise` stream, give the far side the ratchet message its sending
/// direction needs, and half-close (M17.6).
///
/// This grants nothing. See [`PairwiseFrame::Open`] for why the session needs it and
/// why meeting that need with a sender key was the defect.
pub async fn open_sending_direction(
    conn: &VoxConnection,
    channel_id: &crate::hash::Digest32,
    session: &mut Session,
    hello: Option<&InitialMessage>,
) -> Result<()> {
    let (mut send, _recv) = open_typed(conn, StreamKind::Pairwise).await?;
    if let Some(initial) = hello {
        let frame = PairwiseFrame::Hello {
            channel_id: *channel_id,
            initial: initial.to_wire(),
        };
        write_frame(&mut send, &frame.to_frame()).await?;
    }
    let sealed = session.encrypt(&[])?.to_wire();
    let frame = PairwiseFrame::Open {
        channel_id: *channel_id,
        sealed,
    };
    write_frame(&mut send, &frame.to_frame()).await?;
    let _ = send.finish();
    Ok(())
}

/// Read the next frame from an already-accepted, already-authorized `pairwise`
/// stream.
///
/// Acting on either frame needs state only the actor holds — the session for
/// `(channel, peer)`, or the prekey ring — so this only reads; [`open_skdm`]
/// decrypts. `Ok(None)` on a clean half-close with no further frames.
pub async fn recv_pairwise(recv: &mut RecvStream) -> Result<Option<PairwiseFrame>> {
    let Some(bytes) = read_frame(recv, MAX_PAIRWISE_FRAME).await? else {
        return Ok(None);
    };
    Ok(Some(PairwiseFrame::from_frame(&bytes)?))
}

/// Open sealed bytes from [`recv_pairwise`] into an SKDM (still unverified — the
/// channel verifies it against the author's admitted key).
pub fn open_skdm(session: &mut Session, sealed: &[u8], now_secs: u64) -> Result<Skdm> {
    let message = Message::from_wire(sealed)?;
    Skdm::open_from(session, &message, now_secs)
}
