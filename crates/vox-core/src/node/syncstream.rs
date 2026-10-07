//! ADR-008 anti-entropy sync on a typed `sync` stream, and the schedule ADR-016
//! specifies for it (§"Sync scheduling").
//!
//! The reconciliation engine is ADR-008's and is used unchanged; this module only
//! opens/accepts the stream and states the policy:
//!
//! - **When.** A session per shared channel on every new connection, every
//!   [`SYNC_INTERVAL_SECS`] while connected, and a push immediately after a local append. The
//!   node's actor keeps that clock, in milliseconds.
//! - **Which mode.** Frontier mode until a channel exceeds
//!   [`RANGE_MODE_AUTHOR_THRESHOLD`] authors, then range reconciliation
//!   ([`should_use_range_mode`]) — the scale rule ADR-008 requires.
//!
//! ## The stream names its channel first
//! A frontier session reconciles **one channel's** log, but a connection is per
//! *peer* (ADR-016 §"Connections") and a peer may share several channels with us —
//! so the ADR-008 frames alone are not enough to know which log to open. The
//! initiator therefore sends a one-field preamble naming the `(channelID, epoch)`
//! before handing the stream to the engine, exactly as the join stream does. The
//! ADR-008 frame sequence itself is untouched; the channelID is not a secret (it is
//! on the board and in the invite link) and the preamble is inside the authenticated
//! stream regardless.
//!
//! ## Blocking, deliberately
//! ADR-008's engine is synchronous, and [`QuicStreamTransport`] bridges it onto
//! async quinn with [`tokio::runtime::Handle::block_on`]. A session therefore runs
//! on a thread that may block — `tokio::task::spawn_blocking` in the node, a plain
//! thread in tests — never inside an async task on a runtime worker.

use quinn::{RecvStream, SendStream};
use tokio::runtime::Handle;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::{QuicStreamTransport, VoxConnection};
use crate::transport::streams::{open_typed, StreamKind};

/// Seconds between periodic sync sessions with a connected peer (ADR-016).
pub const SYNC_INTERVAL_SECS: u64 = 30;

/// Author count above which a channel reconciles in **range** mode instead of
/// frontier mode (ADR-008 at scale).
pub const RANGE_MODE_AUTHOR_THRESHOLD: usize = 100;

/// Whether a channel with `authors` admitted authors should use range
/// reconciliation rather than frontier mode.
#[must_use]
pub fn should_use_range_mode(authors: usize) -> bool {
    authors > RANGE_MODE_AUTHOR_THRESHOLD
}

/// The largest sync preamble either side will read (`[channel_id, epoch]`).
const MAX_SYNC_PREAMBLE: usize = 64;

/// Open a `sync`-typed bi-stream on `conn` for one channel and wrap it as the
/// ADR-008 transport. The kind frame is written first so the peer dispatches it,
/// then the preamble naming the channel (see the module docs).
pub async fn open_sync(
    conn: &VoxConnection,
    handle: Handle,
    channel_id: &Digest32,
    epoch: u64,
) -> Result<QuicStreamTransport> {
    let (mut send, recv) = open_typed(conn, StreamKind::Sync).await?;
    let mut e = Encoder::new();
    e.array(2).bytes(channel_id).uint(epoch);
    write_frame(&mut send, &e.finish()).await?;
    Ok(QuicStreamTransport::new(handle, send, recv))
}

/// Read the preamble from an accepted `sync` stream: which `(channelID, epoch)` the
/// peer wants to reconcile.
pub async fn read_sync_request(recv: &mut quinn::RecvStream) -> Result<(Digest32, u64)> {
    let bytes = read_frame(recv, MAX_SYNC_PREAMBLE)
        .await?
        .ok_or(Error::MalformedGovernance(
            "sync stream closed before preamble",
        ))?;
    let mut d = Decoder::new(&bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedGovernance("sync preamble arity"));
    }
    let channel_id: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("sync preamble room id"))?;
    let epoch = d.uint()?;
    d.finish()?;
    Ok((channel_id, epoch))
}

/// Wrap an already-accepted, already-authorized `sync` stream as the ADR-008
/// transport (the manager accepted and classified it).
#[must_use]
pub fn accept_sync(handle: Handle, send: SendStream, recv: RecvStream) -> QuicStreamTransport {
    QuicStreamTransport::new(handle, send, recv)
}
