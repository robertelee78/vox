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

use quinn::RecvStream;

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
                    .map_err(|_| Error::MalformedBundle("pairwise room id length"))?,
                sealed: d.bytes()?.to_vec(),
            },
            (OP_SKDM, 3) => Self::Skdm {
                channel_id: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("pairwise room id length"))?,
                sealed: d.bytes()?.to_vec(),
            },
            (OP_HELLO, 3) => Self::Hello {
                channel_id: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("pairwise room id length"))?,
                initial: d.bytes()?.to_vec(),
            },
            _ => return Err(Error::MalformedBundle("pairwise frame op")),
        };
        d.finish()?;
        Ok(frame)
    }
}

/// The frame that carries `initial`, the opening message of a session this node started from
/// the peer's bundle record, ahead of what it opens the session for on the same stream.
#[must_use]
pub fn hello_frame(channel_id: &crate::hash::Digest32, initial: &InitialMessage) -> Vec<u8> {
    PairwiseFrame::Hello {
        channel_id: *channel_id,
        initial: initial.to_wire(),
    }
    .to_frame()
}

/// Seal `skdm` into `session` as one frame for `channel_id`. Sealing steps the ratchet, so it
/// happens where the session lives (the actor), in the order the frames are written.
///
/// # Errors
/// The session could not seal it.
pub fn skdm_frame(
    channel_id: &crate::hash::Digest32,
    session: &mut Session,
    skdm: &Skdm,
) -> Result<Vec<u8>> {
    let sealed = skdm.seal_into(session)?.to_wire();
    Ok(PairwiseFrame::Skdm {
        channel_id: *channel_id,
        sealed,
    }
    .to_frame())
}

/// One ratchet message carrying nothing, which gives the far side a sending direction
/// (M17.6). It grants nothing: see [`PairwiseFrame::Open`].
///
/// # Errors
/// The session could not seal it.
pub fn open_frame(channel_id: &crate::hash::Digest32, session: &mut Session) -> Result<Vec<u8>> {
    let sealed = session.encrypt(&[])?.to_wire();
    Ok(PairwiseFrame::Open {
        channel_id: *channel_id,
        sealed,
    }
    .to_frame())
}

/// How long writing a key, or a hello, to a peer may take. The frames are a few KiB on a live
/// connection, so anything near this is a peer withholding credit, not a slow network.
pub const WRITE_PATIENCE: std::time::Duration = std::time::Duration::from_secs(5);

/// Open a `pairwise` stream on `conn`, write `frames` (already sealed), and half-close.
/// The stream's lifetime is the delivery: the receive half is returned so the caller can learn
/// whether a key was taken (see [`refused`]).
///
/// Bounded by [`WRITE_PATIENCE`], and awaited by the node's per-peer writer, **never on the
/// actor** (V210-71): a peer that grants no stream or flow credit would otherwise hold the whole
/// node for as long as it liked.
///
/// # Errors
/// The stream would not open or take the frames in time.
pub async fn write_pairwise(conn: &VoxConnection, frames: &[Vec<u8>]) -> Result<RecvStream> {
    let written = async {
        let (mut send, recv) = open_typed(conn, StreamKind::Pairwise).await?;
        for f in frames {
            write_frame(&mut send, f).await?;
        }
        let _ = send.finish();
        Ok::<RecvStream, Error>(recv)
    };
    tokio::time::timeout(WRITE_PATIENCE, written)
        .await
        .map_err(|_| Error::Unreachable("the peer did not take a pairwise stream in time"))?
}

/// The recipient's answer on a pairwise stream that carried a key it took.
pub const KEY_TAKEN: u8 = 1;

/// Why a recipient did not take a key, sent as the stream's reset code so the sender can say.
///
/// One code per cause, on purpose: a single "refused" made every cause look alike, and the one
/// case this exists for (two joiners whose keys never land) could not be told apart from the others.
/// Chosen above every `WireError` code, which a refusal at accept still uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefusal {
    /// No pairwise session with the sender for that room.
    NoSession = 0x21,
    /// A session exists, but the key did not open under it (the two ends hold different sessions).
    CannotOpen = 0x22,
    /// The key opened, but the room would not take it (not held, or refused by the room).
    NotAccepted = 0x23,
    /// The hello in front of the key was not accepted, so the key behind it was never read.
    HelloRefused = 0x24,
    /// The key opened, but its owner has not trusted the member it came from, so this node does
    /// not read that member (V210-118). Sent again, and taken, once its owner trusts it.
    NotTrusted = 0x25,
}

impl KeyRefusal {
    /// The stream reset code.
    #[must_use]
    pub fn code(self) -> quinn::VarInt {
        quinn::VarInt::from_u32(self as u32)
    }

    /// Words for a reset code a recipient sent back.
    #[must_use]
    pub fn describe(code: u64) -> String {
        match code {
            0x21 => "no pairwise session for that room".into(),
            0x22 => "the key did not open under the session it holds".into(),
            0x23 => "the room would not take the key".into(),
            0x24 => "its hello was not accepted".into(),
            0x25 => "its owner has not trusted us, so it does not read us yet".into(),
            0x05 => "refused at accept: it may not take a key from us yet".into(),
            other => format!("reset with code {other}"),
        }
    }
}

/// Whether the far side refused a delivered key: `Some(why)` if so, `None` if it took it.
///
/// **Written is not delivered.** QUIC acknowledges the bytes before the recipient has decided
/// anything, so the transport cannot say whether a key was taken. The recipient answers instead,
/// with [`KEY_TAKEN`] once the key is taken, or by resetting the stream with a wire code when it
/// is not: refused at accept, no session to open it with, or a key it could not open. Anything
/// but that one byte (a reset, the stream ending unanswered, the connection lost, or no answer
/// within `patience`) counts as not taken. Sending a key twice is harmless; never sending it
/// leaves a member unable to read. Awaited on its own task, never on the actor: the answer
/// comes after the recipient's actor has handled the key.
pub async fn refused(recv: quinn::RecvStream, patience: std::time::Duration) -> Option<String> {
    refusal(recv, patience).await.map(|(why, _)| why)
}

/// [`refused`], and whether the recipient **answered**: `true` for a refusal it made (a reset with
/// a code, or a wrong byte), `false` when the key never reached a decision (the connection lost,
/// the stream ended unanswered, no answer in time).
pub async fn refusal(
    mut recv: quinn::RecvStream,
    patience: std::time::Duration,
) -> Option<(String, bool)> {
    let mut byte = [0u8; 1];
    match tokio::time::timeout(patience, recv.read_exact(&mut byte)).await {
        Ok(Ok(())) if byte[0] == KEY_TAKEN => None,
        Ok(Ok(())) => Some((format!("answered {}", byte[0]), true)),
        Ok(Err(quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code)))) => {
            Some((KeyRefusal::describe(code.into_inner()), true))
        }
        Ok(Err(e)) => Some((e.to_string(), false)),
        Err(_) => Some((format!("no answer within {}s", patience.as_secs()), false)),
    }
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
