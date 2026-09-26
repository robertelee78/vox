//! The real M5 [`Transport`] over a reliable QUIC
//! bi-stream.
//!
//! M5 frames are opaque byte vectors; here they are length-delimited on the stream
//! with the [`crate::transport::framing`] 4-byte big-endian length prefix so the
//! byte stream is re-segmented into exactly the frames M5 sent. The synchronous M5
//! sync engine is bridged onto async quinn via a tokio runtime [`Handle`].

use std::time::Duration;

use quinn::{RecvStream, SendStream};
use tokio::runtime::Handle;

use crate::error::{Error, Result};
use crate::log::sync::Transport;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::{close_code, VoxConnection, MAX_STREAM_FRAME};
use crate::wire::WireError;

/// How long one sync frame may take to arrive or to be accepted for sending before
/// the session is failed.
///
/// A session runs with the channel's lock held (the ADR-008 engine is synchronous
/// over channel state), so a peer that stops answering — its actor busy, its
/// network gone — would otherwise hold that lock for as long as it liked, and every
/// other use of the channel on this node would wait behind it: a join to answer, a
/// key to take, a message to send. Twenty seconds is far longer than any real
/// exchange and shorter than anyone waits.
pub const SYNC_FRAME_TIMEOUT: Duration = Duration::from_secs(20);

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
    /// `None` while [`Transport::start_serving`]'s writer owns it.
    send: Option<SendStream>,
    /// The writer serving concurrently with the drain, and how to tell it the session was closed.
    writer: Option<(
        tokio::task::JoinHandle<Result<()>>,
        tokio::sync::oneshot::Sender<quinn::VarInt>,
    )>,
    recv: RecvStream,
    /// Set once closed so further sends fail (mirrors the M5 duplex contract).
    closed: Option<WireError>,
    /// Per-frame bound on both directions; see [`SYNC_FRAME_TIMEOUT`].
    frame_timeout: Duration,
}

impl QuicStreamTransport {
    /// Wrap an opened `(SendStream, RecvStream)` pair, bridged onto `handle`, with
    /// the standard [`SYNC_FRAME_TIMEOUT`].
    #[must_use]
    pub fn new(handle: Handle, send: SendStream, recv: RecvStream) -> Self {
        Self::with_timeout(handle, send, recv, SYNC_FRAME_TIMEOUT)
    }

    /// [`QuicStreamTransport::new`] with an explicit per-frame bound.
    #[must_use]
    pub fn with_timeout(
        handle: Handle,
        send: SendStream,
        recv: RecvStream,
        frame_timeout: Duration,
    ) -> Self {
        Self {
            handle,
            send: Some(send),
            writer: None,
            recv,
            closed: None,
            frame_timeout,
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
            return Err(Error::Unreachable("quic transport: send after close"));
        }
        let Some(send) = self.send.as_mut() else {
            return Err(Error::Unreachable("quic transport: send while serving"));
        };
        let bound = self.frame_timeout;
        self.handle
            .block_on(async move {
                tokio::time::timeout(bound, write_frame(send, frame))
                    .await
                    .map_err(|_| Error::Unreachable("sync: peer stopped taking frames"))
            })
            .and_then(|r| r)
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        // A clean FIN exactly at a frame boundary is the peer's success
        // half-close → `Ok(None)`; anything else is a real transport failure.
        let recv = &mut self.recv;
        let bound = self.frame_timeout;
        self.handle
            .block_on(async move {
                tokio::time::timeout(bound, read_frame(recv, MAX_STREAM_FRAME))
                    .await
                    .map_err(|_| Error::Unreachable("sync: peer went quiet"))
            })
            .and_then(|r| r)
    }

    fn close(&mut self, code: WireError) {
        if self.closed.is_some() {
            return;
        }
        self.closed = Some(code);
        // Reset the send side with the mapped QUIC code, and stop the recv side. A writer that
        // owns the send side resets it itself.
        if let Some((_, cancel)) = self.writer.take() {
            let _ = cancel.send(close_code(code));
        }
        if let Some(send) = self.send.as_mut() {
            let _ = send.reset(close_code(code));
        }
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
        if let Some(send) = self.send.as_mut() {
            let _ = send.finish();
        }
    }

    fn start_serving(&mut self, frames: Vec<Vec<u8>>, deadline: std::time::Instant) -> Result<()> {
        if self.closed.is_some() {
            return Err(Error::Unreachable("quic transport: send after close"));
        }
        let Some(mut send) = self.send.take() else {
            return Err(Error::Unreachable("quic transport: already serving"));
        };
        let bound = self.frame_timeout;
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<quinn::VarInt>();
        let task = self.handle.spawn(async move {
            let outcome = {
                let work = async {
                    for f in &frames {
                        if std::time::Instant::now() >= deadline {
                            break;
                        }
                        tokio::time::timeout(bound, write_frame(&mut send, f))
                            .await
                            .map_err(|_| {
                                Error::Unreachable("sync: peer stopped taking frames")
                            })??;
                    }
                    // The clean end-of-stream the peer's drain waits for.
                    let _ = send.finish();
                    Ok::<(), Error>(())
                };
                tokio::pin!(work);
                tokio::select! {
                    r = &mut work => Ok(r),
                    code = &mut cancel_rx => Err(code),
                }
            };
            match outcome {
                Ok(r) => r,
                // The session was closed with a code while serving: say so on the stream.
                Err(Ok(code)) => {
                    let _ = send.reset(code);
                    Ok(())
                }
                // The transport was dropped without a close, so the session ended in error part-way.
                // Reset, never finish: a dropped `SendStream` finishes itself, and the peer would read
                // a truncated batch as a clean end and report success (adr-020_adr-021's review).
                Err(Err(_)) => {
                    let _ = send.reset(close_code(WireError::TransportFailed));
                    Ok(())
                }
            }
        });
        self.writer = Some((task, cancel_tx));
        Ok(())
    }

    fn finish_serving(&mut self) -> Result<()> {
        let Some((task, _cancel)) = self.writer.take() else {
            return Ok(());
        };
        self.handle.block_on(task).unwrap_or(Err(Error::Unreachable(
            "sync: the serving task ended abnormally",
        )))
    }
}
