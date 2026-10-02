//! Typed streams (ADR-016 §"Connections, reachability and sync"): every logical
//! flow on a [`VoxConnection`] opens its own bi-stream and **types it by its first
//! frame**, so the accepting side can dispatch — `sync`, `join`, `pairwise`,
//! `rendezvous`, `tunnel`, `coord`, `circuit` — without a side channel. The kind frame is a
//! one-element canonical-CBOR array `[kind]`; an unknown kind is refused before
//! any flow-specific bytes are read.

use quinn::{RecvStream, SendStream};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::VoxConnection;

/// The logical flow a bi-stream carries, declared by its first frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StreamKind {
    /// ADR-008 anti-entropy sync (frontier or range mode).
    Sync = 1,
    /// The ADR-005 authenticated join exchange.
    Join = 2,
    /// Pairwise sealed control messages (SKDM delivery, ADR-006).
    Pairwise = 3,
    /// The ADR-012 rendezvous service (`PUT`/`GET` records).
    Rendezvous = 4,
    /// An ADR-013 tunnel.
    Tunnel = 5,
    /// Hole-punch coordination (ADR-012 DCUtR) relayed through an anchor.
    Coord = 6,
    /// A relay circuit (ADR-012 rung 4): QUIC packets carried through a peer.
    Circuit = 7,
    /// **"I am stopping"** (V210-93): the last thing a stopping node says on each connection,
    /// before it closes it. It carries nothing past its kind frame.
    ///
    /// A close alone is one datagram that is never sent again, and quinn (0.11.19 and earlier,
    /// quinn-rs/quinn#2785) does not send it at all while the connection's congestion window or
    /// pacer holds back stream data still queued: the close waits behind that data, the
    /// connection's closing period ends first, and the peer hears nothing. It then counts the node
    /// as up until its probing says otherwise, and reports a clean stop as silence. A stream is
    /// delivered like any data, so this is said while the connection still runs.
    Goodbye = 8,
    /// **May a newcomer take a place in a room?** (V210-128): the member answering a join asks
    /// every member it is connected to, and joins only with every answer a yes, so a room never
    /// exceeds its cap. See `node::admitstream`. Members only.
    Admit = 9,
}

/// The largest kind frame we will read: `[kind]` is 2 bytes; anything bigger is
/// not a kind frame.
const MAX_KIND_FRAME: usize = 16;

impl StreamKind {
    /// Resolve a kind from its wire value.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Sync),
            2 => Some(Self::Join),
            3 => Some(Self::Pairwise),
            4 => Some(Self::Rendezvous),
            5 => Some(Self::Tunnel),
            6 => Some(Self::Coord),
            7 => Some(Self::Circuit),
            8 => Some(Self::Goodbye),
            9 => Some(Self::Admit),
            _ => None,
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The canonical kind frame `[kind]`.
    #[must_use]
    pub fn frame(self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(1).uint(u64::from(self.as_u8()));
        e.finish()
    }

    /// Parse a kind frame.
    pub fn parse(frame: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(frame);
        if d.array()? != 1 {
            return Err(Error::MalformedBundle("stream kind arity"));
        }
        let v = u8::try_from(d.uint()?).map_err(|_| Error::MalformedBundle("stream kind range"))?;
        d.finish()?;
        Self::from_u8(v).ok_or(Error::MalformedBundle("unknown stream kind"))
    }
}

/// Open a bi-stream on `conn` typed as `kind` (the kind frame is written first).
pub async fn open_typed(
    conn: &VoxConnection,
    kind: StreamKind,
) -> Result<(SendStream, RecvStream)> {
    let (mut send, recv) = conn.open_stream().await?;
    write_frame(&mut send, &kind.frame()).await?;
    Ok((send, recv))
}

/// Accept the next bi-stream on `conn` and read its kind frame. A stream the peer
/// closes before typing it, or types with an unknown kind, is an error.
pub async fn accept_typed(conn: &VoxConnection) -> Result<(StreamKind, SendStream, RecvStream)> {
    accept_typed_on(conn.quinn()).await
}

/// [`accept_typed`] on the bare quinn handle, for a caller that must wait for streams
/// **without holding the [`VoxConnection`]** — the node's per-connection stream loop, which
/// would otherwise count as a user of the connection for as long as the connection lives.
pub async fn accept_typed_on(
    conn: &quinn::Connection,
) -> Result<(StreamKind, SendStream, RecvStream)> {
    let (send, recv) = conn
        .accept_bi()
        .await
        .map_err(|_| Error::Unreachable("quic stream: the connection is closed"))?;
    read_kind(send, recv).await
}

/// Read the kind frame of a bi-stream already accepted. Waits at most
/// [`crate::transport::framing::FRAME_PATIENCE`] for it, so a caller that accepts in a loop must
/// run this on a task of its own: a peer that opens a stream and withholds its kind would
/// otherwise hold every stream it opens after it.
pub async fn read_kind(
    send: SendStream,
    mut recv: RecvStream,
) -> Result<(StreamKind, SendStream, RecvStream)> {
    let frame = read_frame(&mut recv, MAX_KIND_FRAME)
        .await?
        .ok_or(Error::MalformedBundle("stream closed before kind"))?;
    let kind = StreamKind::parse(&frame)?;
    Ok((kind, send, recv))
}
