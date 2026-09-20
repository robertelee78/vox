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
}

impl PairwiseFrame {
    /// Canonical frame bytes: `[1, sealed]`.
    #[must_use]
    pub fn to_frame(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        match self {
            Self::Skdm { channel_id, sealed } => {
                e.array(3).uint(OP_SKDM).bytes(channel_id).bytes(sealed);
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
            (OP_SKDM, 3) => Self::Skdm {
                channel_id: d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedBundle("pairwise channel_id length"))?,
                sealed: d.bytes()?.to_vec(),
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
pub async fn deliver_skdm(
    conn: &VoxConnection,
    channel_id: &crate::hash::Digest32,
    session: &mut Session,
    skdm: &Skdm,
) -> Result<()> {
    let (mut send, _recv) = open_typed(conn, StreamKind::Pairwise).await?;
    send_skdm(&mut send, channel_id, session, skdm).await?;
    let _ = send.finish();
    Ok(())
}

/// Read the next frame from an already-accepted, already-authorized `pairwise`
/// stream, returning which channel it is for and the still-sealed bytes.
///
/// Opening it needs the session for `(channel, peer)`, which only the actor knows,
/// so the two steps are separate: this reads, [`open_skdm`] decrypts. `Ok(None)` on
/// a clean half-close with no further frames.
pub async fn recv_pairwise(
    recv: &mut RecvStream,
) -> Result<Option<(crate::hash::Digest32, Vec<u8>)>> {
    let Some(bytes) = read_frame(recv, MAX_PAIRWISE_FRAME).await? else {
        return Ok(None);
    };
    let PairwiseFrame::Skdm { channel_id, sealed } = PairwiseFrame::from_frame(&bytes)?;
    Ok(Some((channel_id, sealed)))
}

/// Open sealed bytes from [`recv_pairwise`] into an SKDM (still unverified — the
/// channel verifies it against the author's admitted key).
pub fn open_skdm(session: &mut Session, sealed: &[u8], now_secs: u64) -> Result<Skdm> {
    let message = Message::from_wire(sealed)?;
    Skdm::open_from(session, &message, now_secs)
}
