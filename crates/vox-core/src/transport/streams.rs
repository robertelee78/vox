//! Typed streams (ADR-016 §"Connections, reachability and sync"): every logical
//! flow on a [`VoxConnection`] opens its own bi-stream and **types it by its first
//! frame**, so the accepting side can dispatch — `sync`, `join`, `pairwise`,
//! `rendezvous`, `tunnel`, `coord` — without a side channel. The kind frame is a
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
    let (send, mut recv) = conn.accept_stream().await?;
    let frame = read_frame(&mut recv, MAX_KIND_FRAME)
        .await?
        .ok_or(Error::MalformedBundle("stream closed before kind"))?;
    let kind = StreamKind::parse(&frame)?;
    Ok((kind, send, recv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_frames_round_trip_and_unknown_is_refused() {
        for k in [
            StreamKind::Sync,
            StreamKind::Join,
            StreamKind::Pairwise,
            StreamKind::Rendezvous,
            StreamKind::Tunnel,
            StreamKind::Coord,
        ] {
            assert_eq!(StreamKind::parse(&k.frame()).unwrap(), k);
            assert_eq!(StreamKind::from_u8(k.as_u8()), Some(k));
        }
        let mut e = Encoder::new();
        e.array(1).uint(7);
        assert!(matches!(
            StreamKind::parse(&e.finish()),
            Err(Error::MalformedBundle("unknown stream kind"))
        ));
        let mut e = Encoder::new();
        e.array(2).uint(1).uint(1);
        assert!(matches!(
            StreamKind::parse(&e.finish()),
            Err(Error::MalformedBundle("stream kind arity"))
        ));
        assert!(StreamKind::parse(&[]).is_err());
    }
}
