//! The real M5 [`Transport`] over a reliable QUIC
//! bi-stream.
//!
//! M5 frames are opaque byte vectors; here they are length-delimited on the stream
//! with the [`crate::transport::framing`] 4-byte big-endian length prefix so the
//! byte stream is re-segmented into exactly the frames M5 sent. The synchronous M5
//! sync engine is bridged onto async quinn via a tokio runtime [`Handle`].

use quinn::{RecvStream, SendStream};
use tokio::runtime::Handle;

use crate::error::{Error, Result};
use crate::log::sync::Transport;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::{close_code, VoxConnection, MAX_STREAM_FRAME};
use crate::wire::WireError;

/// A [`sync::Transport`](crate::log::sync::Transport) over one reliable QUIC
/// bi-stream, bridging the synchronous M5 sync engine onto async quinn via a tokio
/// runtime [`Handle`].
///
/// M5 frames are opaque byte vectors; here they are length-delimited on the stream
/// with a 4-byte big-endian length prefix so the byte stream is re-segmented into
/// exactly the frames M5 sent. `recv` returns `Ok(None)` on a clean peer
/// half-close (FIN). A hard [`WireError`] close resets the stream with the mapped
/// QUIC code.
pub struct QuicStreamTransport {
    handle: Handle,
    send: SendStream,
    recv: RecvStream,
    /// Set once closed so further sends fail (mirrors the M5 duplex contract).
    closed: Option<WireError>,
}

impl QuicStreamTransport {
    /// Wrap an opened `(SendStream, RecvStream)` pair, bridged onto `handle`.
    #[must_use]
    pub fn new(handle: Handle, send: SendStream, recv: RecvStream) -> Self {
        Self {
            handle,
            send,
            recv,
            closed: None,
        }
    }

    /// Open a new bi-stream on `conn` and wrap it (initiator side).
    pub async fn open(handle: Handle, conn: &VoxConnection) -> Result<Self> {
        let (send, recv) = conn.open_stream().await?;
        Ok(Self::new(handle, send, recv))
    }

    /// Accept the next bi-stream on `conn` and wrap it (responder side).
    pub async fn accept(handle: Handle, conn: &VoxConnection) -> Result<Self> {
        let (send, recv) = conn.accept_stream().await?;
        Ok(Self::new(handle, send, recv))
    }
}

impl Transport for QuicStreamTransport {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if self.closed.is_some() {
            return Err(Error::MalformedBundle("quic transport: send after close"));
        }
        let send = &mut self.send;
        self.handle.block_on(write_frame(send, frame))
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        // A clean FIN exactly at a frame boundary is the peer's success
        // half-close → `Ok(None)`; anything else is a real transport failure.
        let recv = &mut self.recv;
        self.handle.block_on(read_frame(recv, MAX_STREAM_FRAME))
    }

    fn close(&mut self, code: WireError) {
        if self.closed.is_some() {
            return;
        }
        self.closed = Some(code);
        // Reset the send side with the mapped QUIC code, and stop the recv side.
        let _ = self.send.reset(close_code(code));
        let _ = self.recv.stop(close_code(code));
    }

    fn finish(&mut self) {
        if self.closed.is_some() {
            return;
        }
        // Clean FIN of the send stream (success terminator): the peer's
        // length-prefix read then hits end-of-stream and `recv` returns `Ok(None)`.
        // `finish` only errors if the stream was already reset/finished, which we
        // guard against above, so the result is safely ignored.
        let _ = self.send.finish();
    }
}
