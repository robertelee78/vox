//! One outgoing bounded exchange. Scheduling and explicit demand live with the node actor;
//! this helper never follows a continuation or starts a second stream.

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::node::history_budget::Job;
use crate::transport::quic::VoxConnection;
use crate::transport::stream_transport::Fence;
use crate::transport::streams::{open_typed, StreamKind};
use crate::wire::WireError;

use super::client::{Received, Receiver};
use super::transport::{Read, Transport};
use super::{Frame, Preamble, Query, MAX_FRAME_BYTES};

/// The caller supplies the same fixed fence/deadline used to create the receiver. It must
/// hold its queue slot and actual buffer charges until this worker has really exited.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn exchange(
    receiver: &Receiver,
    conn: &VoxConnection,
    job: Job,
    preamble: Preamble,
    query: Query,
    fence: Arc<Fence>,
    deadline: tokio::time::Instant,
) -> Result<Received> {
    query.validate()?;
    let opening = job
        .reserve(1024)
        .ok_or(Error::Unreachable("history opening buffer busy"))?;
    let streams = tokio::select! {
        biased;
        () = fence.retired() => return Err(Error::Unreachable("history opening cancelled")),
        result = tokio::time::timeout_at(deadline, open_typed(conn, StreamKind::Sync)) => {
            result.map_err(|_| Error::Unreachable("history opening deadline elapsed"))??
        }
    };
    let mut io = Transport::new(streams.0, streams.1, job, fence, deadline);
    let kind_bytes = StreamKind::Sync.frame().len() + 4;
    drop(opening);
    let result = handshake_and_pull(receiver, &mut io, preamble, query, kind_bytes).await;
    if let Err(error) = &result {
        io.abort(match error {
            Error::MalformedBundle(_) | Error::SizeLimitExceeded(_) => WireError::ProtocolLimits,
            _ => WireError::TransportFailed,
        });
    }
    result
}

async fn handshake_and_pull(
    receiver: &Receiver,
    io: &mut Transport,
    preamble: Preamble,
    query: Query,
    kind_bytes: usize,
) -> Result<Received> {
    let mut overhead = kind_bytes + io.write_preamble(preamble).await?;
    let hello = Frame::Hello(crate::wire::SYNC_MODE_BOUNDED_HISTORY);
    let Some(encoded) = hello.encode(io.job())? else {
        return Err(Error::Unreachable("history HELLO buffer busy"));
    };
    overhead += encoded.as_slice().len() + 4;
    io.write_encoded(&encoded).await?;
    drop(encoded);
    let reply = match io.read(MAX_FRAME_BYTES + 4).await? {
        Read::Frame(frame) => frame,
        Read::Busy => return Err(Error::Unreachable("history HELLO reader busy")),
        Read::End => return Err(Error::Unreachable("history closed before HELLO")),
    };
    if !matches!(reply.frame()?, Frame::Hello(mode) if mode == crate::wire::SYNC_MODE_BOUNDED_HISTORY)
    {
        return Err(Error::MalformedBundle("history HELLO mode"));
    }
    overhead += reply.wire_len();
    drop(reply);
    let want = Frame::Want {
        request: preamble.request,
        query: query.clone(),
    };
    let Some(encoded) = want.encode(io.job())? else {
        return Err(Error::Unreachable("history WANT buffer busy"));
    };
    overhead += encoded.as_slice().len() + 4;
    io.write_encoded(&encoded).await?;
    drop(encoded);
    if matches!(query, Query::Inventory) {
        let super::source::Lookup::Found(mut held) = receiver.inventory(io.job()).await? else {
            return Err(Error::Unreachable("history inventory buffers busy"));
        };
        let frame = Frame::Have(std::mem::take(&mut held.value));
        let Some(encoded) = frame.encode(io.job())? else {
            return Err(Error::Unreachable("history inventory writer busy"));
        };
        overhead += encoded.as_slice().len() + 4;
        if overhead + super::DONE_RESERVE > super::MAX_RESPONSE_BYTES {
            return Err(Error::SizeLimitExceeded("inventory handshake quantum"));
        }
        io.write_encoded(&encoded).await?;
        drop(encoded);
        drop(frame);
        drop(held);
    }
    receiver.pull(io, preamble.request, query, overhead).await
}
