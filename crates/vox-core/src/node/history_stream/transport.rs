//! Cancellable I/O for one bounded request. No room or actor lock crosses an await, and no
//! shared admission crosses an await on the peer.

use std::sync::Arc;

use quinn::{RecvStream, SendStream};

use super::{Encoded, Frame, MAX_FRAME_BYTES};
use crate::error::{Error, Result};
use crate::node::history_budget::Job;
use crate::transport::framing::write_frame;
use crate::transport::stream_transport::Fence;
use crate::wire::WireError;

pub(super) struct Incoming {
    bytes: Vec<u8>,
}

impl Incoming {
    pub(super) fn frame(&self) -> Result<Frame<'_>> {
        Frame::decode(&self.bytes)
    }

    pub(super) fn wire_len(&self) -> usize {
        self.bytes.len() + 4
    }
}

pub(super) enum Read {
    Frame(Incoming),
    End,
}

/// The asking side of one loop request, and the holder's side of an incoming request before its
/// admission and after its answer is assembled: the request and its answer's frames are the
/// connection's private assembly (ADR-054 PL-6), bounded by the frame and wire credit, never by
/// the node's shared work or byte admission. It holds no job and no shared byte credit, so no
/// local work waits behind its wait for the peer; the connection's end ends it.
pub(super) struct Private {
    send: SendStream,
    recv: RecvStream,
    fence: Arc<Fence>,
}

impl Private {
    pub(super) fn new(send: SendStream, recv: RecvStream, fence: Arc<Fence>) -> Self {
        Self { send, recv, fence }
    }

    /// One length-prefixed frame (or the preamble), written as the peer's flow control lets.
    pub(super) async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let fence = Arc::clone(&self.fence);
        let result = tokio::select! {
            biased;
            () = fence.retired() => Err(Error::Unreachable("history request cancelled")),
            result = write_frame(&mut self.send, bytes) => result,
        };
        if let Err(error) = &result {
            self.abort(error_code(error));
        }
        result
    }

    /// One frame of at most `remaining_wire` bytes with its prefix, of one of `expected_tags`.
    pub(super) async fn read(
        &mut self,
        remaining_wire: usize,
        expected_tags: Option<&[u8]>,
    ) -> Result<Read> {
        let maximum = remaining_wire.saturating_sub(4).min(MAX_FRAME_BYTES);
        if maximum == 0 {
            return Err(Error::SizeLimitExceeded("history response credit"));
        }
        let fence = Arc::clone(&self.fence);
        let result = tokio::select! {
            biased;
            () = fence.retired() => Err(Error::Unreachable("history request cancelled")),
            result = read_frame(&mut self.recv, maximum, expected_tags) => result,
        };
        if let Err(error) = &result {
            self.abort(error_code(error));
        }
        result
    }

    pub(super) fn abort(&mut self, code: WireError) {
        let code = quinn::VarInt::from_u32(u32::from(code.code()));
        let _ = self.send.reset(code);
        let _ = self.recv.stop(code);
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        self.send
            .finish()
            .map_err(|_| Error::Unreachable("history stream closed before finish"))
    }
}

/// The holder's answer to one request, assembled under its daemon-wide job before any of it is
/// written: the job admits the local work (store reads, proofs, encoding); each encoded frame then
/// leaves the shared byte pool and is kept here as the connection's own bytes, at most the
/// request's wire credit (`credit::Response`, at most `MAX_RESPONSE_BYTES`). The answer awaits
/// nothing from its asker: `serve` gives back the job and every shared charge before it writes
/// these frames (`history_stream::serve`).
pub(super) struct Transport {
    job: Job,
    frames: Vec<Vec<u8>>,
}

impl Transport {
    pub(super) fn new(job: Job) -> Self {
        Self {
            job,
            frames: Vec::new(),
        }
    }

    pub(super) fn job(&self) -> &Job {
        &self.job
    }

    /// Add one frame the credit ledger has accepted. Its encoding charge is given back here; the
    /// bytes are the connection's own from now on.
    pub(super) fn push(&mut self, encoded: Encoded) {
        let Encoded { bytes, .. } = encoded;
        self.frames.push(bytes);
    }

    /// The assembled frames, in order; the job goes with the rest of `self`.
    pub(super) fn into_frames(self) -> Vec<Vec<u8>> {
        self.frames
    }
}

async fn read_frame(
    recv: &mut RecvStream,
    maximum: usize,
    expected_tags: Option<&[u8]>,
) -> Result<Read> {
    let mut prefix = [0; 4];
    match recv.read_exact(&mut prefix).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(Read::End),
        Err(error) => return Err(read_error(error)),
    }
    let len = u32::from_be_bytes(prefix) as usize;
    if len == 0 || len > maximum {
        return Err(Error::SizeLimitExceeded("history frame length/credit"));
    }
    let mut bytes = vec![0; len];
    recv.read_exact(&mut bytes).await.map_err(read_error)?;
    if expected_tags.is_some_and(|expected| !expected.contains(&bytes[0])) {
        return Err(Error::MalformedBundle("history unexpected fixed frame"));
    }
    Ok(Read::Frame(Incoming { bytes }))
}

fn read_error(error: quinn::ReadExactError) -> Error {
    if let quinn::ReadExactError::ReadError(quinn::ReadError::Reset(code)) = error {
        if let Some(reason) = u8::try_from(code.into_inner())
            .ok()
            .and_then(WireError::from_code)
        {
            return Error::PeerRefused(reason);
        }
    }
    Error::Unreachable("history stream closed partway through a frame")
}

fn error_code(error: &Error) -> WireError {
    match error {
        Error::SizeLimitExceeded(_) | Error::MalformedBundle(_) => WireError::ProtocolLimits,
        _ => WireError::TransportFailed,
    }
}
