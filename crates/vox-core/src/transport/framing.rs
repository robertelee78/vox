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

/// Read one length-prefixed frame of at most `max_len` bytes. A clean FIN
/// *exactly at* a frame boundary is the peer's success half-close → `Ok(None)`;
/// a FIN partway through a frame, a reset, or an announced length above
/// `max_len` is an error.
pub async fn read_frame(recv: &mut RecvStream, max_len: usize) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(_) => return Err(Error::MalformedBundle("quic stream read len")),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(Error::SizeLimitExceeded("quic stream frame length"));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|_| Error::MalformedBundle("quic stream read body"))?;
    Ok(Some(body))
}
