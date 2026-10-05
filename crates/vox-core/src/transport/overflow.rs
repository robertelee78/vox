//! **Receiver overflow** (ADR-024 RO-1–RO-7, #218 R41a): a receiver says when its own socket
//! dropped what reached it, so the sender does not take that for congestion on the path.
//!
//! A receiver behind a short socket buffer (a container on a host that keeps Linux's default
//! `net.core.rmem_max`, granted 416 KiB) that stops reading for a moment (a VM pause, a throttled
//! cgroup) loses whatever arrives past the buffer. Its sender's Cubic read every such loss as
//! congestion and cut, and at a 50 ms round trip never regrew between stalls: R41's WAN arm fell to
//! 9–10% of raw with the receiver stopped 20 ms in every 100 ms, against 99.8% with a 4 MiB buffer.
//! The path was never congested; the receiver's socket was full.
//!
//! ## The receiver
//! The endpoint samples its UDP socket's own drop count ([`vox_sockdrops::recv_drops`],
//! `SO_MEMINFO`) every [`SAMPLE_EVERY`] while the socket is receiving, and each connection sends
//! its peer the count, cumulative, in a control datagram when it has changed and the peer has
//! sent it something since the last one. Linux and Android only: elsewhere there is no
//! per-socket count, nothing is sent, and nothing changes. A connection over a relay circuit
//! sends none: what reaches it comes through the relay's connection, so this socket's drops say
//! nothing about its path.
//!
//! ## The wire
//! A Vox datagram starts with a varint flow id, and a flow binds a **bidirectional** stream
//! ([`crate::transport::router`]), so a unidirectional stream's id never names one. Flow
//! [`CONTROL_FLOW`] (3, a server-initiated unidirectional id) carries Vox's own:
//!
//! ```text
//! control  := varint 3 ‖ varint kind ‖ body
//! kind 0   := overflow report: varint epoch ‖ varint drops
//! kind ≥1  := reserved: dropped and counted as an unknown flow
//! ```
//!
//! `epoch` is drawn at random when the socket is bound, so a receiver that restarted is never
//! read as a count that went backwards; `drops` is the socket's cumulative count, as read. A lost
//! report costs nothing lasting: the next carries the total.
//!
//! ## The sender
//! Each report's increase over the last, in packets, is **credit**, kept in the connection's
//! [`OverflowLedger`] and good for one smoothed round trip (never under [`CREDIT_FLOOR`]). The
//! controller (`taper::Tapered`) spends it on a loss of the same number of packets: a loss the
//! credit already covers costs no cut; a cut whose loss the credit covers within one round trip of
//! it is undone. Either way the loss is taken back out of the path signals, so overflow neither
//! climbs a tier nor holds one. A loss with a queue building, an ECN mark, persistent congestion
//! and anything in tier 3 are never spent on: on a congested path the receiver's count does not
//! move, and nothing changes there.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::transport::datagram::{put_varint, take_varint};

/// The flow id of Vox's control datagrams: a server-initiated unidirectional stream's, which no
/// flow can bind.
pub const CONTROL_FLOW: u64 = 3;

/// The control datagram that reports a socket's overflow.
pub const KIND_OVERFLOW: u64 = 0;

/// How often a receiving socket's drop count is read, while it is receiving.
pub const SAMPLE_EVERY: Duration = Duration::from_millis(5);

/// The least time a report's credit is good for, whatever the round trip: two samples, so a LAN
/// whose round trip is shorter than the sampling still gets its cuts back.
pub const CREDIT_FLOOR: Duration = Duration::from_millis(10);

/// At most this many losses wait for a report to cover them.
pub(crate) const PENDING_MAX: usize = 8;

/// An overflow report, as sent: `varint 3 ‖ varint 0 ‖ varint epoch ‖ varint drops`.
#[must_use]
pub fn encode_report(epoch: u32, drops: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    put_varint(&mut out, CONTROL_FLOW);
    put_varint(&mut out, KIND_OVERFLOW);
    put_varint(&mut out, u64::from(epoch));
    put_varint(&mut out, u64::from(drops));
    out
}

/// An overflow report's `(epoch, drops)`, from what follows the control flow's id; `None` for
/// another kind or a malformed body.
#[must_use]
pub fn decode_report(rest: &[u8]) -> Option<(u32, u32)> {
    let (kind, rest) = take_varint(rest)?;
    if kind != KIND_OVERFLOW {
        return None;
    }
    let (epoch, rest) = take_varint(rest)?;
    let (drops, rest) = take_varint(rest)?;
    if !rest.is_empty() {
        return None;
    }
    Some((u32::try_from(epoch).ok()?, u32::try_from(drops).ok()?))
}

/// What a connection's peer has reported of its socket's overflow, for the controller to spend
/// (see the module docs). Shared between the connection's datagram reader, which writes it, and
/// its congestion controller, which reads it in its own callbacks.
#[derive(Debug, Default)]
pub struct OverflowLedger {
    state: Mutex<LedgerState>,
    reports: AtomicU64,
    skipped: AtomicU64,
    undone: AtomicU64,
}

#[derive(Debug, Default)]
struct LedgerState {
    /// The last report: its epoch and its count.
    last: Option<(u32, u32)>,
    /// Unspent credit, in packets, with when it arrived, oldest first.
    credit: VecDeque<(Instant, u64)>,
}

/// What `vox status --json` says of a connection's overflow reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OverflowStats {
    /// Reports sent to the peer: this end's socket overflowed while it read from it.
    pub reports_sent: u64,
    /// Reports received from the peer.
    pub reports_received: u64,
    /// Packets of credit not yet spent. Credit past its round trip is dropped at the next spend,
    /// so this may count some that can no longer be spent.
    pub credit_packets: u64,
    /// Losses that cost no cut, the peer having reported them first.
    pub cuts_skipped: u64,
    /// Cuts taken back once the peer reported their loss.
    pub cuts_undone: u64,
}

impl OverflowLedger {
    fn state(&self) -> std::sync::MutexGuard<'_, LedgerState> {
        // Each critical section is a few field updates with no `.await`: a poisoned lock is safe.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The peer reports `drops` on its socket of `epoch`, at `now`: an increase over the last
    /// report of the same epoch is credit. A first report, or one of a new epoch, only sets the
    /// mark.
    pub fn report(&self, epoch: u32, drops: u32, now: Instant) {
        self.reports.fetch_add(1, Ordering::Relaxed);
        let mut s = self.state();
        if let Some((last_epoch, last_drops)) = s.last {
            if last_epoch == epoch {
                let more = u64::from(drops.wrapping_sub(last_drops));
                if more > 0 && more < u64::from(u32::MAX / 2) {
                    s.credit.push_back((now, more));
                }
            }
        }
        s.last = Some((epoch, drops));
    }

    /// Spend `need` packets of credit no older than `life`, oldest first, all or nothing.
    pub(crate) fn take(&self, need: u64, now: Instant, life: Duration) -> bool {
        let mut s = self.state();
        while s
            .credit
            .front()
            .is_some_and(|&(at, _)| now.saturating_duration_since(at) > life)
        {
            s.credit.pop_front();
        }
        let have: u64 = s.credit.iter().map(|&(_, n)| n).sum();
        if need == 0 || have < need {
            return false;
        }
        let mut left = need;
        while left > 0 {
            let Some(front) = s.credit.front_mut() else {
                break;
            };
            if front.1 > left {
                front.1 -= left;
                left = 0;
            } else {
                left -= front.1;
                s.credit.pop_front();
            }
        }
        true
    }

    pub(crate) fn note_skipped(&self) {
        self.skipped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn note_undone(&self) {
        self.undone.fetch_add(1, Ordering::Relaxed);
    }

    /// The counts for `vox status --json`; `reports_sent` is the connection's, filled in there.
    #[must_use]
    pub fn stats(&self) -> OverflowStats {
        OverflowStats {
            reports_sent: 0,
            reports_received: self.reports.load(Ordering::Relaxed),
            credit_packets: self.state().credit.iter().map(|&(_, n)| n).sum(),
            cuts_skipped: self.skipped.load(Ordering::Relaxed),
            cuts_undone: self.undone.load(Ordering::Relaxed),
        }
    }
}
