//! Charged, cancellable I/O for one bounded request. No room or actor lock crosses an await.

use std::sync::Arc;

use quinn::{RecvStream, SendStream};
use tokio::time::Instant;

use super::{
    Encoded, Frame, ACK_FRAME_MAX_BYTES, MAX_FRAME_BYTES, MAX_HELLO_FRAME_BYTES,
    MAX_WANT_FRAME_BYTES,
};
use crate::error::{Error, Result};
use crate::node::history_budget::{BufferCharge, Job};
use crate::transport::framing::write_frame;
use crate::transport::stream_transport::{Fence, SYNC_FRAME_TIMEOUT};
use crate::wire::WireError;

// Covers a parsed HAVE vector or all bounded proof tokens/headers beside the raw input.
// The separate verification slice owns context maps and verifier outputs, not this decoder.
const DECODE_ENVELOPE: usize = 1024 * 1024;

pub(super) struct Incoming {
    bytes: Vec<u8>,
    _charge: BufferCharge,
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
    Busy,
}

pub(super) struct Transport {
    send: SendStream,
    recv: RecvStream,
    job: Job,
    fence: Arc<Fence>,
    deadline: Instant,
}

impl Transport {
    pub(super) fn new(
        send: SendStream,
        recv: RecvStream,
        job: Job,
        fence: Arc<Fence>,
        deadline: Instant,
    ) -> Self {
        Self {
            send,
            recv,
            job,
            fence,
            deadline,
        }
    }

    pub(super) fn job(&self) -> &Job {
        &self.job
    }

    fn until(&self) -> Instant {
        self.deadline.min(Instant::now() + SYNC_FRAME_TIMEOUT)
    }

    /// The caller supplies its remaining response credit including the four-byte prefix.
    /// Reserve before reading even that prefix: Busy never leaves a partially consumed frame.
    pub(super) async fn read(&mut self, remaining_wire: usize) -> Result<Read> {
        self.read_bounded(remaining_wire, DECODE_ENVELOPE, None)
            .await
    }

    /// HELLO has a fixed three-byte maximum and no decoded collection. Keep its reservation
    /// ahead of the prefix while leaving the attacker-sized envelope on every variable frame.
    pub(super) async fn read_hello(&mut self) -> Result<Read> {
        self.read_bounded(MAX_HELLO_FRAME_BYTES + 4, 0, Some(&[0x01]))
            .await
    }

    /// This handshake position accepts WANT's bounded scalar Query or a smaller CANCEL.
    pub(super) async fn read_want_or_cancel(&mut self) -> Result<Read> {
        self.read_bounded(MAX_WANT_FRAME_BYTES + 4, 0, Some(&[0x03, 0x09]))
            .await
    }

    /// ACK and CANCEL are fixed scalar frames. They need no variable-frame decode envelope;
    /// reserve their structural bound before the prefix and reject every other tag there.
    pub(super) async fn read_ack_or_cancel(&mut self, remaining_wire: usize) -> Result<Read> {
        self.read_bounded(
            remaining_wire.min(ACK_FRAME_MAX_BYTES + 4),
            0,
            Some(&[0x0A, 0x09]),
        )
        .await
    }

    async fn read_bounded(
        &mut self,
        remaining_wire: usize,
        decode_envelope: usize,
        expected_tags: Option<&[u8]>,
    ) -> Result<Read> {
        let maximum = remaining_wire.saturating_sub(4).min(MAX_FRAME_BYTES);
        if maximum == 0 {
            return Err(Error::SizeLimitExceeded("history response credit"));
        }
        let envelope = maximum
            .checked_add(decode_envelope)
            .ok_or(Error::SizeLimitExceeded("history frame envelope"))?;
        let Some(work_job) = self.job.record_job(envelope) else {
            return Ok(Read::Busy);
        };
        let Some(charge) = work_job.reserve(envelope) else {
            return Ok(Read::Busy);
        };
        let until = self.until();
        let fence = Arc::clone(&self.fence);
        let result = tokio::select! {
            biased;
            () = fence.retired() => Err(Error::Unreachable("history request cancelled")),
            result = tokio::time::timeout_at(
                until,
                read_charged(&mut self.recv, maximum, charge, expected_tags),
            ) => {
                result.unwrap_or(Err(Error::Unreachable("history frame deadline elapsed")))
            }
        };
        if let Err(error) = &result {
            self.abort(error_code(error));
        }
        result
    }

    /// False is local buffer exhaustion before any bytes are sent. The encoded allocation and
    /// its permit remain held through the complete write, including transport backpressure.
    pub(super) async fn write(&mut self, frame: &Frame<'_>) -> Result<bool> {
        let Some(encoded) = frame.encode(&self.job)? else {
            return Ok(false);
        };
        self.write_encoded(&encoded).await?;
        Ok(true)
    }

    /// The credit ledger measures this exact encoding before it commits wire credit. Keeping
    /// it charged here avoids re-encoding after the ledger has accepted a frame.
    pub(super) async fn write_encoded(&mut self, encoded: &Encoded) -> Result<()> {
        self.write_bytes(encoded.as_slice()).await
    }

    /// The fixed preamble is charged separately from ordinary frame encodings.
    pub(super) async fn write_preamble(&mut self, preamble: super::Preamble) -> Result<usize> {
        let _charge = self
            .job
            .reserve(super::MAX_PREAMBLE * 2)
            .ok_or(Error::Unreachable("history preamble buffer busy"))?;
        let bytes = preamble.encode();
        self.write_bytes(&bytes).await?;
        Ok(bytes.len() + 4)
    }

    async fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let until = self.until();
        let fence = Arc::clone(&self.fence);
        let result = tokio::select! {
            biased;
            () = fence.retired() => Err(Error::Unreachable("history request cancelled")),
            result = tokio::time::timeout_at(until, write_frame(&mut self.send, bytes)) => {
                result.unwrap_or(Err(Error::Unreachable("history frame deadline elapsed")))
            }
        };
        if let Err(error) = &result {
            self.abort(error_code(error));
        }
        result
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        self.send
            .finish()
            .map_err(|_| Error::Unreachable("history stream closed before finish"))
    }

    pub(super) fn abort(&mut self, code: WireError) {
        let code = quinn::VarInt::from_u32(u32::from(code.code()));
        let _ = self.send.reset(code);
        let _ = self.recv.stop(code);
    }
}

async fn read_charged(
    recv: &mut RecvStream,
    maximum: usize,
    charge: BufferCharge,
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
    Ok(Read::Frame(Incoming {
        bytes,
        _charge: charge,
    }))
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
