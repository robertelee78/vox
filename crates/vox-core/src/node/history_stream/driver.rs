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
use super::{Frame, Preamble, Query};

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
    let opening = job.reserve_or_pressure(1024)?;
    let streams = tokio::select! {
        biased;
        () = fence.retired() => return Err(Error::Unreachable("history opening cancelled")),
        result = tokio::time::timeout_at(deadline, open_typed(conn, StreamKind::Sync)) => {
            result.map_err(|_| Error::Unreachable("history opening deadline elapsed"))??
        }
    };
    let mut io = Transport::new(
        streams.0,
        streams.1,
        job,
        fence,
        deadline,
        conn.supports_availability().then_some(conn.serial()),
    );
    let kind_bytes = StreamKind::Sync.frame().len() + 4;
    drop(opening);
    let result = handshake_and_pull(
        receiver,
        &mut io,
        preamble,
        query,
        kind_bytes,
        conn.serial(),
    )
    .await;
    if let Err(error) = &result {
        io.abort(match error {
            Error::HistoryCapacity(_) => WireError::SessionBusy,
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
    connection_serial: u64,
) -> Result<Received> {
    let mut overhead = kind_bytes + io.write_preamble(preamble).await?;
    let hello = Frame::Hello(crate::wire::SYNC_MODE_BOUNDED_HISTORY);
    let encoded = hello.encode_required(io.job())?;
    overhead += encoded.as_slice().len() + 4;
    io.write_encoded(&encoded).await?;
    drop(encoded);
    let reply = match io.read_hello_required().await? {
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
    let encoded = want.encode_required(io.job())?;
    overhead += encoded.as_slice().len() + 4;
    io.write_encoded(&encoded).await?;
    drop(encoded);
    let mut announcement = None;
    let mut catalog_announcement = None;
    let mut offered_availability = None;
    if matches!(query, Query::Inventory) {
        let super::source::Lookup::Found(mut held) = receiver.inventory(io.job()).await? else {
            return Err(Error::Unreachable("history inventory buffers busy"));
        };
        offered_availability = io.availability_connection.map(|_| held.value.4);
        let frame = Frame::Have {
            hints: std::mem::take(&mut held.value.0),
            role: held.value.1.as_ref().map(|notice| notice.head),
            key_catalog: held.value.2,
            availability: offered_availability,
        };
        let encoded = frame.encode_required(io.job())?;
        overhead += encoded.as_slice().len() + 4;
        if overhead + super::DONE_RESERVE > super::MAX_RESPONSE_BYTES {
            return Err(Error::SizeLimitExceeded("inventory handshake quantum"));
        }
        io.write_encoded(&encoded).await?;
        announcement = held.value.1.take();
        catalog_announcement = held.value.3.take();
        drop(encoded);
        drop(frame);
        drop(held);
    }
    let mut result = receiver.pull(io, preamble.request, query, overhead).await?;
    if result.status == super::Status::Complete {
        result.offered_availability = offered_availability;
        if let Some(announcement) = announcement {
            receiver.acknowledge_role(io.job(), announcement).await?;
        }
        if let Some(announcement) = catalog_announcement {
            receiver
                .acknowledge_key_catalog(io.job(), announcement, connection_serial)
                .await?;
        }
    }
    Ok(result)
}
