//! Length-delimited frames on a reliable QUIC bi-stream (ADR-011 §"Two contracts
//! on one connection"): every stream flow — M5 sync, the rendezvous service, the
//! join stream — carries a sequence of opaque frames, each prefixed by its 4-byte
//! big-endian length, so the byte stream is re-segmented into exactly the
//! messages the sender framed.
//!
//! These are the async primitives; [`crate::transport::stream_transport`] bridges
//! them to the synchronous M5 engine. A caller supplies the per-flow frame cap so
//! a hostile peer cannot announce a huge length to force an allocation.

use quinn::{RecvStream, SendStream};

use crate::error::{Error, Result};

/// Write one length-prefixed frame.
pub async fn write_frame(send: &mut SendStream, frame: &[u8]) -> Result<()> {
    let len = u32::try_from(frame.len())
        .map_err(|_| Error::SizeLimitExceeded("quic stream frame length"))?;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|_| Error::MalformedBundle("quic stream write len"))?;
    send.write_all(frame)
        .await
        .map_err(|_| Error::MalformedBundle("quic stream write body"))?;
    Ok(())
}

/// How long one frame may take to arrive before the peer is treated as gone.
///
/// **A read on a network stream must never be unbounded.** The connection's own liveness
/// does not save you: Vox keeps connections alive with a QUIC keep-alive, so quinn happily
/// PINGs a connection for ever while a *stream* on it sends nothing at all. A peer that
/// opens a stream and says nothing therefore waits for ever unless the read says otherwise.
///
/// Generous, because a frame can legitimately be slow: a relayed circuit carries QUIC inside
/// a QUIC stream through a third party, and a join does a proof of work at the far end. The
/// cost of being wrong is one stream the peer must open again; the cost of no bound is a node
/// that stops answering.
pub const FRAME_PATIENCE: std::time::Duration = std::time::Duration::from_secs(30);

/// Read one length-prefixed frame of at most `max_len` bytes, waiting at most
/// [`FRAME_PATIENCE`]. A clean FIN *exactly at* a frame boundary is the peer's success
/// half-close → `Ok(None)`; a FIN partway through a frame, a reset, an announced length above
/// `max_len`, or a peer that stops talking mid-frame is an error.
pub async fn read_frame(recv: &mut RecvStream, max_len: usize) -> Result<Option<Vec<u8>>> {
    read_frame_within(recv, max_len, FRAME_PATIENCE).await
}

/// [`read_frame`] with an explicit bound, for a caller that knows its own timing.
pub async fn read_frame_within(
    recv: &mut RecvStream,
    max_len: usize,
    patience: std::time::Duration,
) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(patience, recv.read_exact(&mut len_buf)).await {
        Ok(Ok(())) => {}
        Ok(Err(quinn::ReadExactError::FinishedEarly(0))) => return Ok(None),
        Ok(Err(_)) => return Err(Error::MalformedBundle("quic stream read len")),
        Err(_) => {
            return Err(Error::Unreachable(
                "quic stream: peer sent no frame in time",
            ))
        }
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(Error::SizeLimitExceeded("quic stream frame length"));
    }
    let mut body = vec![0u8; len];
    match tokio::time::timeout(patience, recv.read_exact(&mut body)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(Error::MalformedBundle("quic stream read body")),
        Err(_) => {
            return Err(Error::Unreachable(
                "quic stream: peer stopped partway through a frame",
            ))
        }
    }
    Ok(Some(body))
}
