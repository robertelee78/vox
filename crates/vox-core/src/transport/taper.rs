//! ADR-024 M24.1 **spike**: tier 2 of the tapered controller on its own. Cubic, except that a
//! loss arriving while the path shows no queueing delay is withheld from it.
//!
//! **Not for merge.** This exists to measure one hypothesis on R41's arms: random (non-congestion)
//! loss is what collapses Cubic on the lossy link, and withholding exactly those losses restores the
//! throughput without costing the clean links anything, because a clean link never loses a packet
//! except to a queue that is full, and a full queue shows as delay.
//!
//! The congestion signal is Veno's: the bytes this connection keeps queued in the path,
//! `window × (1 − min_rtt / rtt)`. At or above `QUEUED_PACKETS` packets of it, a loss is congestion
//! and Cubic sees it. Below that, it is noise and Cubic does not. An ECN mark (`lost_bytes == 0`)
//! and persistent congestion always reach Cubic.

use std::any::Any;
use std::sync::Arc;
use std::time::Instant;

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics, CubicConfig};
use quinn_proto::RttEstimator;

/// How many packets of standing queue this connection must hold for a loss to count as
/// congestion (Veno's β).
const QUEUED_PACKETS: u64 = 3;

/// Builds [`LossAware`] controllers.
#[derive(Debug, Default)]
pub struct LossAwareConfig {
    cubic: CubicConfig,
}

impl ControllerFactory for LossAwareConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(LossAware {
            cubic: Arc::new(self.cubic.clone()).build(now, current_mtu),
            mtu: u64::from(current_mtu),
            rtt: None,
            min_rtt: None,
            withheld: 0,
            passed: 0,
        })
    }
}

/// Cubic behind a filter that withholds losses the path's delay says were not congestion.
pub struct LossAware {
    cubic: Box<dyn Controller>,
    mtu: u64,
    rtt: Option<std::time::Duration>,
    min_rtt: Option<std::time::Duration>,
    withheld: u64,
    passed: u64,
}

impl LossAware {
    /// Bytes this connection is estimated to keep queued in the path (Veno's backlog).
    fn queued(&self) -> Option<u64> {
        let (rtt, min) = (self.rtt?, self.min_rtt?);
        if rtt.is_zero() || min >= rtt {
            return Some(0);
        }
        let share = 1.0 - min.as_secs_f64() / rtt.as_secs_f64();
        Some((self.cubic.window() as f64 * share) as u64)
    }
}

impl Controller for LossAware {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.cubic.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.rtt = Some(rtt.get());
        self.min_rtt = Some(rtt.min());
        self.cubic.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.cubic
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        let congested = is_persistent_congestion
            || lost_bytes == 0
            || self
                .queued()
                .map_or(true, |q| q >= QUEUED_PACKETS * self.mtu);
        if congested {
            self.passed += 1;
            self.cubic
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        } else {
            self.withheld += 1;
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu);
        self.cubic.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.cubic.window()
    }

    fn metrics(&self) -> ControllerMetrics {
        self.cubic.metrics()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(LossAware {
            cubic: self.cubic.clone_box(),
            mtu: self.mtu,
            rtt: self.rtt,
            min_rtt: self.min_rtt,
            withheld: self.withheld,
            passed: self.passed,
        })
    }

    fn initial_window(&self) -> u64 {
        self.cubic.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl Drop for LossAware {
    fn drop(&mut self) {
        // SPIKE instrumentation: how many losses each way, per connection, so the R41 run shows
        // whether the filter acted on the lossy arm and stayed out of the clean ones.
        if self.withheld + self.passed > 0 {
            eprintln!(
                "SPIKE taper: losses passed to Cubic {}, withheld {}",
                self.passed, self.withheld
            );
        }
    }
}
