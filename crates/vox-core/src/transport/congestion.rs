//! Congestion control for Vox connections: quinn's Cubic, **restarted after an idle
//! period** (PRD-001 R41).
//!
//! # Why a restart
//! A node keeps one QUIC connection per peer, and every tunnel to that peer shares it — and so
//! shares one congestion controller for as long as the connection lives, which may be days.
//! Cubic remembers: after losses its slow-start threshold and its `W_max` stay low, and the next
//! bulk transfer grows in congestion avoidance, one segment at a time, however long the
//! connection sat idle and whatever the path looks like now.
//!
//! Measured through the shipped binaries on an emulated 1 Gbit/s, 50 ms path that followed a
//! 2 ms LAN arm with ordinary drop-tail losses: the connection entered the long path at a 3.7 MB
//! window and plateaued there, ~590 Mbit/s, for the whole transfer. The same transfer on a
//! connection without that history reached 98% of the link. A plain TCP transfer — `scp`, say —
//! is a fresh connection each time, starts in slow start and finds the path's capacity within a
//! few round trips; a tunnel should not do worse because its connection is older.
//!
//! So once the connection has sent nothing for [`IDLE_RESTART`] (and several round trips), the
//! next send starts from a fresh controller: the initial window, in slow start, with no memory of
//! a path that may have changed. That is what the transfer would have had on a connection of its
//! own. RFC 5681 §4.1 also restarts after idle, but keeps the old slow-start threshold, which
//! would leave exactly the plateau measured above.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics, CubicConfig};
use quinn_proto::RttEstimator;

/// How long a connection must have sent nothing before its next send starts from a fresh
/// controller. Long enough that the gaps inside one transfer (an application pausing between
/// writes, a request/response exchange) never trigger it; short enough that a new transfer
/// after a pause is treated as one.
pub const IDLE_RESTART: Duration = Duration::from_secs(1);

/// The idle period also has to span this many smoothed round trips, so a very long path is not
/// restarted between two flights of the same transfer.
const IDLE_RTTS: u32 = 4;

/// Builds `IdleRestart` controllers around quinn's Cubic.
#[derive(Debug, Default)]
pub struct IdleRestartConfig {
    cubic: Arc<CubicConfig>,
}

impl ControllerFactory for IdleRestartConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(IdleRestart {
            inner: Arc::clone(&self.cubic).build(now, current_mtu),
            factory: Arc::clone(&self.cubic),
            mtu: current_mtu,
            last_sent: None,
            srtt: Duration::ZERO,
        })
    }
}

/// Cubic, rebuilt from scratch when the connection goes idle. See the module docs.
struct IdleRestart {
    inner: Box<dyn Controller>,
    factory: Arc<CubicConfig>,
    mtu: u16,
    last_sent: Option<Instant>,
    srtt: Duration,
}

impl Controller for IdleRestart {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        let idle = IDLE_RESTART.max(self.srtt * IDLE_RTTS);
        if self
            .last_sent
            .is_some_and(|t| now.saturating_duration_since(t) > idle)
        {
            self.inner = Arc::clone(&self.factory).build(now, self.mtu);
        }
        self.last_sent = Some(now);
        self.inner.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.srtt = rtt.get();
        self.inner.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.inner
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.inner
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.inner.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.inner.window()
    }

    fn metrics(&self) -> ControllerMetrics {
        self.inner.metrics()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            inner: self.inner.clone_box(),
            factory: Arc::clone(&self.factory),
            mtu: self.mtu,
            last_sent: self.last_sent,
            srtt: self.srtt,
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
