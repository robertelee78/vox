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

/// A session's **fence** (ADR-025 D1a): once retired, a session stops at its next room step or
/// transport operation. Aborting the task that started a session does not stop a worker already
/// running it on a blocking thread, so the worker is told this way instead, and a transport
/// operation it is blocked in returns at once, resetting the stream.
#[derive(Debug, Default)]
pub struct Fence {
    retired: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl Fence {
    /// A new, unretired fence.
    #[must_use]
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::default())
    }

    /// Retire the session: every later check fails, and a wait in progress ends.
    pub fn retire(&self) {
        self.retired
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Whether the session has been retired.
    #[must_use]
    pub fn is_retired(&self) -> bool {
        self.retired.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Resolves once the session is retired.
    pub async fn retired(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_retired() {
                return;
            }
            notified.await;
        }
    }
}

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
    /// The code the peer reset or stopped the stream with, once it has (see
    /// [`Transport::peer_refused`]).
    peer_refused: Option<WireError>,
    /// The session's fence, if it has one (ADR-025 D1a).
    fence: Option<std::sync::Arc<Fence>>,
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
            peer_refused: None,
            fence: None,
        }
    }

    /// Stop every transport operation once `fence` is retired (ADR-025 D1a).
    #[must_use]
    pub fn fenced(mut self, fence: std::sync::Arc<Fence>) -> Self {
        self.fence = Some(fence);
        self
    }

    /// Whether the fence is retired; if so the stream is reset, once.
    fn check_fence(&mut self) -> Result<()> {
        if self.fence.as_ref().is_some_and(|f| f.is_retired()) {
            self.close(WireError::TransportFailed);
            return Err(Error::Unreachable("sync: the session was retired"));
        }
        Ok(())
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
        self.check_fence()?;
        if self.closed.is_some() {
            return Err(Error::Unreachable("quic transport: send after close"));
        }
        let Some(send) = self.send.as_mut() else {
            return Err(Error::Unreachable("quic transport: send while serving"));
        };
        let bound = self.frame_timeout;
        let fence = self.fence.clone();
        let r = self
            .handle
            .block_on(async move {
                let work = async {
                    tokio::time::timeout(bound, write_frame(send, frame))
                        .await
                        .map_err(|_| Error::Unreachable("sync: peer stopped taking frames"))
                };
                match fence {
                    Some(f) => tokio::select! {
                        r = work => r,
                        () = f.retired() => Err(Error::Unreachable("sync: the session was retired")),
                    },
                    None => work.await,
                }
            })
            .and_then(|r| r);
        self.note_refusal(&r);
        self.check_fence()?;
        r
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        // A clean FIN exactly at a frame boundary is the peer's success
        // half-close → `Ok(None)`; anything else is a real transport failure.
        self.check_fence()?;
        let recv = &mut self.recv;
        let bound = self.frame_timeout;
        let fence = self.fence.clone();
        let r = self
            .handle
            .block_on(async move {
                let work = async {
                    tokio::time::timeout(bound, read_frame(recv, MAX_STREAM_FRAME))
                        .await
                        .map_err(|_| Error::Unreachable("sync: peer went quiet"))
                };
                match fence {
                    Some(f) => tokio::select! {
                        r = work => r,
                        () = f.retired() => Err(Error::Unreachable("sync: the session was retired")),
                    },
                    None => work.await,
                }
            })
            .and_then(|r| r);
        self.note_refusal(&r);
        self.check_fence()?;
        r
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
                    #[cfg(feature = "mutant-sender")]
                    let pace = crate::log::sync::mutant::pace();
                    #[cfg(not(feature = "mutant-sender"))]
                    let pace: Option<std::time::Duration> = None;
                    for f in &frames {
                        if let Some(gap) = pace {
                            tokio::time::sleep(gap).await;
                        } else if std::time::Instant::now() >= deadline {
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
        let Some((mut task, cancel)) = self.writer.take() else {
            return Ok(());
        };
        let fence = self.fence.clone();
        let done = self.handle.block_on(async {
            match fence {
                Some(f) => tokio::select! {
                    r = &mut task => Some(r),
                    () = f.retired() => None,
                },
                None => Some((&mut task).await),
            }
        });
        match done {
            Some(r) => r.unwrap_or(Err(Error::Unreachable(
                "sync: the serving task ended abnormally",
            ))),
            None => {
                // Retired while serving: the writer resets the stream and stops.
                let _ = cancel.send(close_code(WireError::TransportFailed));
                self.closed = Some(WireError::TransportFailed);
                let _ = self.recv.stop(close_code(WireError::TransportFailed));
                Err(Error::Unreachable("sync: the session was retired"))
            }
        }
    }

    fn peer_refused(&self) -> Option<WireError> {
        self.peer_refused
    }
}

impl QuicStreamTransport {
    /// Remember the peer's refusal, the first time one comes back from the stream.
    fn note_refusal<T>(&mut self, r: &Result<T>) {
        if let (None, Err(Error::PeerRefused(code))) = (self.peer_refused, r) {
            self.peer_refused = Some(*code);
        }
    }
}
