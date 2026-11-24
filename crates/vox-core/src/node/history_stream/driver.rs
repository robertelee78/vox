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
    introduction: &[Vec<u8>],
) -> Result<Received> {
    query.validate()?;
    // Ledger 91: the first time this connection is used for the room, this node's own board
    // records go to the peer's board, and the request waits for the board's answer. A member the
    // peer does not know yet is then on its board, so the Sync stream gate takes it and the
    // peer's roster admission runs on the request itself. A refusal as a stranger puts them again.
    if !conn.introduced(&preamble.room) && !board_offer_mutant() {
        introduce(conn, introduction, &fence, deadline).await;
        conn.note_introduced(preamble.room, true);
    }
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
    if matches!(
        result,
        Err(Error::PeerRefused(
            WireError::NotYetMember | WireError::AuthenticatorInvalid
        ))
    ) {
        conn.note_introduced(preamble.room, false);
    }
    if let Err(error) = &result {
        io.abort(match error {
            Error::HistoryCapacity(_) => WireError::SessionBusy,
            Error::MalformedBundle(_) | Error::SizeLimitExceeded(_) => WireError::ProtocolLimits,
            _ => WireError::TransportFailed,
        });
    }
    result
}

/// Put this node's own board records (its bundle, then its address record, whose key the bundle
/// carries) on the peer's board, and wait for its answer. A refusal is the peer's board policy
/// speaking (an older claim, a record it already holds): the request goes on either way.
async fn introduce(
    conn: &VoxConnection,
    records: &[Vec<u8>],
    fence: &Fence,
    deadline: tokio::time::Instant,
) {
    if records.is_empty() {
        return;
    }
    let put = async {
        let mut client = crate::nat::service::RendezvousClient::open(conn).await?;
        for record in records {
            let _ = client.put(record).await;
        }
        client.finish();
        Ok::<_, Error>(())
    };
    tokio::select! {
        biased;
        () = fence.retired() => {}
        _ = tokio::time::timeout_at(deadline, put) => {}
    }
}

/// `VOX_MUTANT_BOARD_OFFER_CONDITIONAL` (test-knobs): a request does not first put this node's
/// records on the peer's board, as before ledger 91 (only the conditional board exchange of a
/// fresh inventory flow or a key waiting on a bundle offered them). Says so once on stderr.
#[cfg(feature = "test-knobs")]
fn board_offer_mutant() -> bool {
    static ON: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        let on = std::env::var_os("VOX_MUTANT_BOARD_OFFER_CONDITIONAL").is_some();
        if on {
            eprintln!("vox: VOX_MUTANT_BOARD_OFFER_CONDITIONAL engaged: no board put first");
        }
        on
    });
    *ON
}

#[cfg(not(feature = "test-knobs"))]
const fn board_offer_mutant() -> bool {
    false
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
    // The authenticated peer already has the room-bound preamble and fixed mode.
    // Pipeline WANT/HAVE so a Public announcement need not wait behind bytes on
    // the reverse path. Validate the peer's HELLO before accepting its response.
    // A head-bound request carries the canonical body of the asker's own held head (ADR-053 P);
    // the asker still verifies every response under that exact signed head.
    let target = match query.target_head() {
        Some(head) => Some(receiver.request_target(io.job(), head).await?),
        None => None,
    };
    #[cfg(feature = "test-knobs")]
    let (query, target, abandon) = hostile_target(query, target);
    let want = Frame::Want {
        request: preamble.request,
        query: query.clone(),
        target,
    };
    let encoded = want.encode_required(io.job())?;
    overhead += encoded.as_slice().len() + 4;
    io.write_encoded(&encoded).await?;
    drop(encoded);
    #[cfg(feature = "test-knobs")]
    if abandon {
        return Err(Error::Unreachable("hostile history request abandoned"));
    }
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
        if overhead + super::MAX_HELLO_FRAME_BYTES + 4 + super::DONE_RESERVE
            > super::MAX_RESPONSE_BYTES
        {
            return Err(Error::SizeLimitExceeded("inventory handshake quantum"));
        }
        io.write_encoded(&encoded).await?;
        announcement = held.value.1.take();
        catalog_announcement = held.value.3.take();
        drop(encoded);
        drop(frame);
        drop(held);
    }
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

/// `VOX_TEST_CYCLE_TARGETS_FILE`: while the file exists this node is a hostile asker for the
/// ADR-053 P guards. Every head-bound request names an unsigned target it does not hold, in
/// turn: a forged root of its own head's size, a size past any holder, and two smaller sizes
/// with forged roots, the second abandoned right after the request is sent. Each is said once
/// on stderr.
#[cfg(feature = "test-knobs")]
fn hostile_target(
    mut query: Query,
    target: Option<crate::log::history::HeadTarget>,
) -> (Query, Option<crate::log::history::HeadTarget>, bool) {
    static SENT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let hostile = std::env::var_os("VOX_TEST_CYCLE_TARGETS_FILE")
        .is_some_and(|path| std::path::Path::new(&path).exists());
    let Some(mut forged) = target.filter(|_| hostile) else {
        return (query, target, false);
    };
    let count = SENT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let size = forged.root.leaves.max(1);
    match count % 4 {
        0 => forged.root.hash[0] ^= 1,
        1 => forged.root.leaves = size + 1_000_000,
        _ => {
            forged.root.leaves = 1 + (count / 4) % size;
            forged.root.controls = 0;
            forged.root.hash = crate::hash::sha256(&count.to_be_bytes());
        }
    }
    query.retarget(forged.id());
    eprintln!(
        "vox: hostile target sent variant={} size={}",
        count % 4,
        forged.root.leaves
    );
    (query, Some(forged), count % 4 == 3)
}
