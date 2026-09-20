//! ADR-008 anti-entropy sync on a typed `sync` stream, and the schedule ADR-016
//! specifies for it (§"Sync scheduling").
//!
//! The reconciliation engine is ADR-008's and is used unchanged; this module only
//! opens/accepts the stream and states the policy:
//!
//! - **When.** A session per shared channel on every new connection
//!   ([`SyncTrigger::Connected`]), every [`SYNC_INTERVAL_SECS`] while connected
//!   ([`SyncTrigger::Periodic`]), and a push immediately after a local append
//!   ([`SyncTrigger::LocalAppend`]). [`SyncSchedule`] is the pure clock-driven
//!   decision, so the node's timer logic is testable without a network.
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

/// Why a sync session is being run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncTrigger {
    /// A connection to this peer was just established.
    Connected,
    /// The periodic interval elapsed.
    Periodic,
    /// This node appended locally and is pushing it out.
    LocalAppend,
}

/// The per-peer sync clock (ADR-016 §"Sync scheduling"), as a pure function of
/// time and local appends so it can be tested without a network.
#[derive(Debug, Clone, Copy)]
pub struct SyncSchedule {
    last_sync: u64,
    pending_append: bool,
}

impl SyncSchedule {
    /// A schedule for a peer that has just connected: the first session is due
    /// immediately.
    #[must_use]
    pub fn connected() -> Self {
        Self {
            last_sync: 0,
            pending_append: false,
        }
    }

    /// Record a local append: the next check pushes it out without waiting for the
    /// interval.
    pub fn note_local_append(&mut self) {
        self.pending_append = true;
    }

    /// Record that a session ran at `now_secs`.
    pub fn note_synced(&mut self, now_secs: u64) {
        self.last_sync = now_secs;
        self.pending_append = false;
    }

    /// The trigger due at `now_secs`, if any. A local append wins over the
    /// interval, and the first call after [`SyncSchedule::connected`] is
    /// `Connected`.
    #[must_use]
    pub fn due(&self, now_secs: u64) -> Option<SyncTrigger> {
        if self.last_sync == 0 {
            return Some(SyncTrigger::Connected);
        }
        if self.pending_append {
            return Some(SyncTrigger::LocalAppend);
        }
        if now_secs.saturating_sub(self.last_sync) >= SYNC_INTERVAL_SECS {
            return Some(SyncTrigger::Periodic);
        }
        None
    }
}

impl Default for SyncSchedule {
    fn default() -> Self {
        Self::connected()
    }
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
        .map_err(|_| Error::MalformedGovernance("sync preamble channel_id"))?;
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
