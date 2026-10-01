//! `VoxBbr`: tier 3 of the tapered congestion controller (ADR-024, M24.4).
//!
//! # What this is
//! quinn-proto 0.11.18's BBR (`congestion/bbr/{mod,bw_estimation,min_max}.rs`), ported into Vox. The
//! model, the gains, the gain cycle, ProbeRtt, recovery and the min-max filter are quinn's;
//! quinn-proto 0.11.19, the newest release, carries the same files byte for byte. quinn is
//! untouched: the decider's rule is that Vox does not patch others' software, and owning the
//! controller is what lets the tapered controller hand a running connection's rate to it.
//!
//! # Where it departs from quinn's, and why
//! quinn's BBR ran a clean 1 Gbit/s LAN at 28% of raw (ADR-024 Context). Two of its estimators
//! were wrong, and both are replaced here:
//! - **The minimum round trip is BBR's own 10-second windowed minimum** of the connection's
//!   samples (`now - sent` per acknowledged packet), as the BBR draft defines `min_rtt`. quinn's
//!   reads `RttEstimator::min()`, the connection's *lifetime* minimum. Measured through the shipped
//!   binary after a warm-up on loopback, it read 0 µs on a 10 ms path for the whole transfer, so
//!   every bandwidth-delay product BBR computed from it was the floor.
//! - **The bandwidth estimate is the BBR draft's delivery-rate sampling**
//!   (draft-cheng-iccrg-delivery-rate-estimation), with every sample fed to the max filter. quinn's
//!   took the smaller of the last send interval's and the last acknowledgement interval's rates and
//!   fed the filter only samples above its maximum, so an overshoot never decayed. Measured on a
//!   200 Mbit/s, 10 ms path with 1% loss: its estimate passed the link rate and the window grew to
//!   eight bandwidth-delay products. See `BandwidthEstimation` below.
//!
//! With both, measured once each through the shipped binary on emulated links: a clean 1 Gbit/s,
//! 2 ms LAN at 962, 962 and 940 Mbit/s against tier 1's 983, 988 and 983; a 200 Mbit/s, 10 ms path
//! with 1% loss at 195.8 Mbit/s, 3.1 times a stock-Cubic flow on the same link.
//!
//! **quinn paces from the window, not from `pacing_rate`.** quinn-proto 0.11.18 reads a
//! controller's pacing rate only for its metrics; its pacer runs from the window and the smoothed
//! round trip. So BBR's gain cycle acts here only through the window (`cwnd_gain`), and BBR is
//! window-bound: it can stand up to one bandwidth-delay product of queue by itself. The tapered
//! controller's tier-3 queue test allows for that (`taper`).
//!
//! # What else is Vox's
//! - [`VoxBbr::seeded`]: a BBR that starts from the rate, minimum round trip and window the
//!   connection has already shown, in ProbeBw, instead of in Startup at the initial window
//!   (ADR-024 rule 5: a switch does not restart the connection's ramp).
//! - [`VoxBbr::delivery_rate`] and [`VoxBbr::min_rtt`], so the tapered controller can hand the
//!   rate back when it leaves tier 3.
//! - The gain cycle's random offset is drawn from the operating system (`getrandom`) once per
//!   ProbeBw entry, instead of from a `rand_pcg` generator seeded the same way; Vox does not
//!   otherwise depend on `rand`.
//! - quinn's `#[cfg(test)]` check of the min-max filter is not carried (Vox has no in-crate tests,
//!   ADR-018).
//!
//! # Licence
//! The ported code is quinn's, used under the MIT licence (quinn-proto is "MIT OR Apache-2.0"):
//!
//! > Copyright (c) 2018 The quinn Developers
//! >
//! > Permission is hereby granted, free of charge, to any person obtaining a copy of this software
//! > and associated documentation files (the "Software"), to deal in the Software without
//! > restriction, including without limitation the rights to use, copy, modify, merge, publish,
//! > distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
//! > Software is furnished to do so, subject to the following conditions:
//! >
//! > The above copyright notice and this permission notice shall be included in all copies or
//! > substantial portions of the Software.
//! >
//! > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
//! > BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//! > NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
//! > DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! > OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//!
//! quinn's BBR is itself based on Google's QUICHE `bbr_sender.cc`, and its min-max filter on
//! Kathleen Nichols' algorithm as released by Google under the BSD licence
//! (<https://groups.google.com/forum/#!topic/bbr-dev/3RTgkzi5ZD8>).

use std::any::Any;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerMetrics};
use quinn_proto::RttEstimator;

/// quinn's base datagram size: the initial window is counted in these.
const BASE_DATAGRAM_SIZE: u64 = 1200;

/// How far back BBR's minimum round trip looks (the BBR draft's `MinRTTFilterLen`).
const MIN_RTT_WINDOW: Duration = Duration::from_secs(10);

/// What a connection hands to a [`VoxBbr`] when it switches tiers (ADR-024 rule 5).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RateSeed {
    /// The delivery rate the path has shown, bytes per second.
    pub(crate) delivery_rate: u64,
    /// The path's minimum round trip.
    pub(crate) min_rtt: Duration,
    /// The congestion window at the moment of the switch, bytes.
    pub(crate) window: u64,
    /// The last packet number the connection sent: BBR's rounds count from it.
    pub(crate) last_sent_pn: u64,
}

/// quinn's BBR (see the module docs): aims for low queueing and full use of a high
/// bandwidth-delay-product path, and does not read random loss as congestion.
#[derive(Debug, Clone)]
pub(crate) struct VoxBbr {
    initial_window: u64,
    current_mtu: u64,
    max_bandwidth: BandwidthEstimation,
    acked_bytes: u64,
    mode: Mode,
    loss_state: LossState,
    recovery_state: RecoveryState,
    recovery_window: u64,
    is_at_full_bandwidth: bool,
    pacing_gain: f32,
    high_gain: f32,
    drain_gain: f32,
    cwnd_gain: f32,
    high_cwnd_gain: f32,
    last_cycle_start: Option<Instant>,
    current_cycle_offset: u8,
    init_cwnd: u64,
    min_cwnd: u64,
    prev_in_flight_count: u64,
    exit_probe_rtt_at: Option<Instant>,
    probe_rtt_last_started_at: Option<Instant>,
    min_rtt: Duration,
    exiting_quiescence: bool,
    pacing_rate: u64,
    max_acked_packet_number: u64,
    max_sent_packet_number: u64,
    end_recovery_at_packet_number: u64,
    cwnd: u64,
    current_round_trip_end_packet_number: u64,
    round_count: u64,
    bw_at_last_round: u64,
    round_wo_bw_gain: u64,
    ack_aggregation: AckAggregationState,
    /// Monotone deque of (time, sample) giving the windowed minimum round trip.
    rtt_mins: VecDeque<(Instant, Duration)>,
}

impl VoxBbr {
    /// A BBR in Startup at the initial window: quinn's `Bbr::new` with `BbrConfig::default()`.
    pub(crate) fn new(_now: Instant, current_mtu: u16) -> Self {
        let initial_window = K_MAX_INITIAL_CONGESTION_WINDOW * BASE_DATAGRAM_SIZE;
        Self {
            initial_window,
            current_mtu: u64::from(current_mtu),
            max_bandwidth: BandwidthEstimation::default(),
            acked_bytes: 0,
            mode: Mode::Startup,
            loss_state: LossState::default(),
            recovery_state: RecoveryState::NotInRecovery,
            recovery_window: 0,
            is_at_full_bandwidth: false,
            pacing_gain: K_DEFAULT_HIGH_GAIN,
            high_gain: K_DEFAULT_HIGH_GAIN,
            drain_gain: 1.0 / K_DEFAULT_HIGH_GAIN,
            cwnd_gain: K_DEFAULT_HIGH_GAIN,
            high_cwnd_gain: K_DEFAULT_HIGH_GAIN,
            last_cycle_start: None,
            current_cycle_offset: 0,
            init_cwnd: initial_window,
            min_cwnd: calculate_min_window(u64::from(current_mtu)),
            prev_in_flight_count: 0,
            exit_probe_rtt_at: None,
            probe_rtt_last_started_at: None,
            min_rtt: Duration::ZERO,
            exiting_quiescence: false,
            pacing_rate: 0,
            max_acked_packet_number: 0,
            max_sent_packet_number: 0,
            end_recovery_at_packet_number: 0,
            cwnd: initial_window,
            current_round_trip_end_packet_number: 0,
            round_count: 0,
            bw_at_last_round: 0,
            round_wo_bw_gain: 0,
            ack_aggregation: AckAggregationState::default(),
            rtt_mins: VecDeque::new(),
        }
    }

    /// A BBR that continues a running connection instead of starting one (ADR-024 rule 5).
    ///
    /// The path's capacity is already known, so this one is past Startup: the bandwidth filter
    /// holds `seed.delivery_rate` as its first sample (it ages out after the filter's ten rounds,
    /// like any other), the minimum round trip is `seed.min_rtt`, measured just now, so ProbeRtt
    /// is not due for another ten seconds, and the window is the one the connection had. It
    /// enters ProbeBw exactly as quinn's BBR does when it leaves Drain, not in recovery.
    /// `seed.last_sent_pn` starts the round count at the connection's own packet numbers, so the
    /// first round ends at the first acknowledgement of a packet sent after the switch.
    pub(crate) fn seeded(now: Instant, current_mtu: u16, seed: RateSeed) -> Self {
        let mut bbr = Self::new(now, current_mtu);
        bbr.max_sent_packet_number = seed.last_sent_pn;
        bbr.max_acked_packet_number = seed.last_sent_pn;
        bbr.current_round_trip_end_packet_number = seed.last_sent_pn;
        if seed.delivery_rate > 0 {
            bbr.max_bandwidth
                .max_filter
                .update_max(bbr.round_count, seed.delivery_rate);
            bbr.bw_at_last_round = seed.delivery_rate;
            bbr.pacing_rate = seed.delivery_rate;
        }
        if !seed.min_rtt.is_zero() {
            bbr.min_rtt = seed.min_rtt;
            bbr.rtt_mins.push_back((now, seed.min_rtt));
        }
        // The ProbeRtt timer starts now either way: a switch is not a reason to drain at once.
        bbr.probe_rtt_last_started_at = Some(now);
        bbr.cwnd = seed.window.max(bbr.min_cwnd);
        bbr.acked_bytes = bbr.init_cwnd;
        bbr.is_at_full_bandwidth = true;
        bbr.enter_probe_bandwidth_mode(now);
        bbr
    }

    /// The delivery rate this BBR's model holds, bytes per second (0 before any sample).
    pub(crate) fn delivery_rate(&self) -> u64 {
        self.max_bandwidth.get_estimate()
    }

    /// The minimum round trip this BBR's model holds (zero before any sample).
    pub(crate) fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// The round trip this BBR can raise by itself on a path whose base round trip is `base`, with
    /// no other flow: its target window (`cwnd_gain` bandwidth-delay products of `base`, plus the
    /// acknowledgement aggregation it measured) drained at its bandwidth estimate. quinn paces from
    /// the window, so this is the queue BBR alone can stand. It is computed from `base`, not from
    /// this model's own minimum round trip, which another flow's standing queue raises; and from the
    /// target, not the current window, which lags a falling estimate: with a Cubic flow taking share
    /// on a 4-BDP buffer, `window / estimate` grew with the very queue it was meant to see.
    pub(crate) fn standing_rtt(&self, base: Duration) -> Duration {
        let bw = self.max_bandwidth.get_estimate();
        if bw == 0 {
            return base;
        }
        let target = K_DERIVED_HIGH_CWNDGAIN as f64 * bw as f64 * base.as_secs_f64()
            + self.ack_aggregation.max_ack_height.get() as f64;
        base.max(Duration::from_secs_f64(target / bw as f64))
    }

    fn enter_startup_mode(&mut self) {
        self.mode = Mode::Startup;
        self.pacing_gain = self.high_gain;
        self.cwnd_gain = self.high_cwnd_gain;
    }

    fn enter_probe_bandwidth_mode(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = K_DERIVED_HIGH_CWNDGAIN;
        self.last_cycle_start = Some(now);
        // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
        // excluded because in that case increased gain and decreased gain would not
        // follow each other.
        let mut rand_index = random_below(K_PACING_GAIN.len() as u8 - 1);
        if rand_index >= 1 {
            rand_index += 1;
        }
        self.current_cycle_offset = rand_index;
        self.pacing_gain = K_PACING_GAIN[rand_index as usize];
    }

    fn update_recovery_state(&mut self, is_round_start: bool) {
        // Exit recovery when there are no losses for a round.
        if self.loss_state.has_losses() {
            self.end_recovery_at_packet_number = self.max_sent_packet_number;
        }
        match self.recovery_state {
            // Enter conservation on the first loss.
            RecoveryState::NotInRecovery if self.loss_state.has_losses() => {
                self.recovery_state = RecoveryState::Conservation;
                // This will cause the |recovery_window| to be set to the
                // correct value in CalculateRecoveryWindow().
                self.recovery_window = 0;
                // Since the conservation phase is meant to be lasting for a whole
                // round, extend the current round as if it were started right now.
                self.current_round_trip_end_packet_number = self.max_sent_packet_number;
            }
            RecoveryState::Growth | RecoveryState::Conservation => {
                if self.recovery_state == RecoveryState::Conservation && is_round_start {
                    self.recovery_state = RecoveryState::Growth;
                }
                // Exit recovery if appropriate.
                if !self.loss_state.has_losses()
                    && self.max_acked_packet_number > self.end_recovery_at_packet_number
                {
                    self.recovery_state = RecoveryState::NotInRecovery;
                }
            }
            _ => {}
        }
    }

    fn update_gain_cycle_phase(&mut self, now: Instant, in_flight: u64) {
        // In most cases, the cycle is advanced after an RTT passes.
        let mut should_advance_gain_cycling = self
            .last_cycle_start
            .map(|last_cycle_start| now.duration_since(last_cycle_start) > self.min_rtt)
            .unwrap_or(false);
        // If the pacing gain is above 1.0, the connection is trying to probe the
        // bandwidth by increasing the number of bytes in flight to at least
        // pacing_gain * BDP.  Make sure that it actually reaches the target, as
        // long as there are no losses suggesting that the buffers are not able to
        // hold that much.
        if self.pacing_gain > 1.0
            && !self.loss_state.has_losses()
            && self.prev_in_flight_count < self.get_target_cwnd(self.pacing_gain)
        {
            should_advance_gain_cycling = false;
        }

        // If pacing gain is below 1.0, the connection is trying to drain the extra
        // queue which could have been incurred by probing prior to it.  If the
        // number of bytes in flight falls down to the estimated BDP value earlier,
        // conclude that the queue has been successfully drained and exit this cycle
        // early.
        if self.pacing_gain < 1.0 && in_flight <= self.get_target_cwnd(1.0) {
            should_advance_gain_cycling = true;
        }

        if should_advance_gain_cycling {
            self.current_cycle_offset = (self.current_cycle_offset + 1) % K_PACING_GAIN.len() as u8;
            self.last_cycle_start = Some(now);
            // Stay in low gain mode until the target BDP is hit.  Low gain mode
            // will be exited immediately when the target BDP is achieved.
            if DRAIN_TO_TARGET
                && self.pacing_gain < 1.0
                && (K_PACING_GAIN[self.current_cycle_offset as usize] - 1.0).abs() < f32::EPSILON
                && in_flight > self.get_target_cwnd(1.0)
            {
                return;
            }
            self.pacing_gain = K_PACING_GAIN[self.current_cycle_offset as usize];
        }
    }

    fn maybe_exit_startup_or_drain(&mut self, now: Instant, in_flight: u64) {
        if self.mode == Mode::Startup && self.is_at_full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = self.drain_gain;
            self.cwnd_gain = self.high_cwnd_gain;
        }
        if self.mode == Mode::Drain && in_flight <= self.get_target_cwnd(1.0) {
            self.enter_probe_bandwidth_mode(now);
        }
    }

    fn is_min_rtt_expired(&self, now: Instant, app_limited: bool) -> bool {
        !app_limited
            && self
                .probe_rtt_last_started_at
                .map(|last| now.saturating_duration_since(last) > Duration::from_secs(10))
                .unwrap_or(true)
    }

    fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: Instant,
        is_round_start: bool,
        bytes_in_flight: u64,
        app_limited: bool,
    ) {
        let min_rtt_expired = self.is_min_rtt_expired(now, app_limited);
        if min_rtt_expired && !self.exiting_quiescence && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            // Do not decide on the time to exit ProbeRtt until the
            // |bytes_in_flight| is at the target small value.
            self.exit_probe_rtt_at = None;
            self.probe_rtt_last_started_at = Some(now);
        }

        if self.mode == Mode::ProbeRtt {
            match self.exit_probe_rtt_at {
                None => {
                    // If the window has reached the appropriate size, schedule exiting
                    // ProbeRtt.  The CWND during ProbeRtt is
                    // kMinimumCongestionWindow, but we allow an extra packet since QUIC
                    // checks CWND before sending a packet.
                    if bytes_in_flight < self.get_probe_rtt_cwnd() + self.current_mtu {
                        const K_PROBE_RTT_TIME: Duration = Duration::from_millis(200);
                        self.exit_probe_rtt_at = Some(now + K_PROBE_RTT_TIME);
                    }
                }
                Some(exit_time) if is_round_start && now >= exit_time => {
                    if !self.is_at_full_bandwidth {
                        self.enter_startup_mode();
                    } else {
                        self.enter_probe_bandwidth_mode(now);
                    }
                }
                Some(_) => {}
            }
        }

        self.exiting_quiescence = false;
    }

    fn get_target_cwnd(&self, gain: f32) -> u64 {
        let bw = self.max_bandwidth.get_estimate();
        let bdp = self.min_rtt.as_micros() as u64 * bw;
        let bdpf = bdp as f64;
        let cwnd = ((gain as f64 * bdpf) / 1_000_000f64) as u64;
        // BDP estimate will be zero if no bandwidth samples are available yet.
        if cwnd == 0 {
            return self.init_cwnd;
        }
        cwnd.max(self.min_cwnd)
    }

    fn get_probe_rtt_cwnd(&self) -> u64 {
        const K_MODERATE_PROBE_RTT_MULTIPLIER: f32 = 0.75;
        if PROBE_RTT_BASED_ON_BDP {
            return self.get_target_cwnd(K_MODERATE_PROBE_RTT_MULTIPLIER);
        }
        self.min_cwnd
    }

    fn calculate_pacing_rate(&mut self) {
        let bw = self.max_bandwidth.get_estimate();
        if bw == 0 {
            return;
        }
        let target_rate = (bw as f64 * self.pacing_gain as f64) as u64;
        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }

        // Pace at the rate of initial_window / RTT as soon as RTT measurements are
        // available.
        if self.pacing_rate == 0 && self.min_rtt.as_nanos() != 0 {
            // quinn unwraps here; the `min_rtt` check above is what makes it infallible.
            if let Some(rate) = BandwidthEstimation::bw_from_delta(self.init_cwnd, self.min_rtt) {
                self.pacing_rate = rate;
            }
            return;
        }

        // Do not decrease the pacing rate during startup.
        if self.pacing_rate < target_rate {
            self.pacing_rate = target_rate;
        }
    }

    fn calculate_cwnd(&mut self, bytes_acked: u64, excess_acked: u64) {
        if self.mode == Mode::ProbeRtt {
            return;
        }
        let mut target_window = self.get_target_cwnd(self.cwnd_gain);
        if self.is_at_full_bandwidth {
            // Add the max recently measured ack aggregation to CWND.
            target_window += self.ack_aggregation.max_ack_height.get();
        } else {
            // Add the most recent excess acked.  Because CWND never decreases in
            // STARTUP, this will automatically create a very localized max filter.
            target_window += excess_acked;
        }
        // Instead of immediately setting the target CWND as the new one, BBR grows
        // the CWND towards |target_window| by only increasing it |bytes_acked| at a
        // time.
        if self.is_at_full_bandwidth {
            self.cwnd = target_window.min(self.cwnd + bytes_acked);
        } else if (self.cwnd_gain < target_window as f32) || (self.acked_bytes < self.init_cwnd) {
            // If the connection is not yet out of startup phase, do not decrease
            // the window.
            self.cwnd += bytes_acked;
        }

        // Enforce the limits on the congestion window.
        if self.cwnd < self.min_cwnd {
            self.cwnd = self.min_cwnd;
        }
    }

    fn calculate_recovery_window(&mut self, bytes_acked: u64, bytes_lost: u64, in_flight: u64) {
        if !self.recovery_state.in_recovery() {
            return;
        }
        // Set up the initial recovery window.
        if self.recovery_window == 0 {
            self.recovery_window = self.min_cwnd.max(in_flight + bytes_acked);
            return;
        }

        // Remove losses from the recovery window, while accounting for a potential
        // integer underflow.
        if self.recovery_window >= bytes_lost {
            self.recovery_window -= bytes_lost;
        } else {
            // k_max_segment_size = current_mtu
            self.recovery_window = self.current_mtu;
        }
        // In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
        // release additional |bytes_acked| to achieve a slow-start-like behavior.
        if self.recovery_state == RecoveryState::Growth {
            self.recovery_window += bytes_acked;
        }

        // Sanity checks.  Ensure that we always allow to send at least an MSS or
        // |bytes_acked| in response, whichever is larger.
        self.recovery_window = self
            .recovery_window
            .max(in_flight + bytes_acked)
            .max(self.min_cwnd);
    }

    /// <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control#section-4.3.2.2>
    fn check_if_full_bw_reached(&mut self, app_limited: bool) {
        if app_limited {
            return;
        }
        let target = (self.bw_at_last_round as f64 * K_STARTUP_GROWTH_TARGET as f64) as u64;
        let bw = self.max_bandwidth.get_estimate();
        if bw >= target {
            self.bw_at_last_round = bw;
            self.round_wo_bw_gain = 0;
            self.ack_aggregation.max_ack_height.reset();
            return;
        }

        self.round_wo_bw_gain += 1;
        if self.round_wo_bw_gain >= K_ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP as u64
            || (self.recovery_state.in_recovery())
        {
            self.is_at_full_bandwidth = true;
        }
    }
}

impl Controller for VoxBbr {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.max_sent_packet_number = last_packet_number;
        self.max_bandwidth.on_sent(now, bytes);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.max_bandwidth
            .on_ack(now, sent, bytes, self.round_count, app_limited);
        self.acked_bytes += bytes;
        // quinn reads `rtt.min()` here; see the module docs for why this is BBR's own window.
        let _ = rtt;
        let sample = now.saturating_duration_since(sent);
        while self.rtt_mins.back().is_some_and(|(_, m)| *m >= sample) {
            self.rtt_mins.pop_back();
        }
        self.rtt_mins.push_back((now, sample));
        while self
            .rtt_mins
            .front()
            .is_some_and(|(t, _)| now.saturating_duration_since(*t) > MIN_RTT_WINDOW)
        {
            self.rtt_mins.pop_front();
        }
        let windowed = self.rtt_mins.front().map_or(sample, |(_, m)| *m);
        if self.is_min_rtt_expired(now, app_limited) || self.min_rtt > windowed {
            self.min_rtt = windowed;
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        let bytes_acked = self.max_bandwidth.bytes_acked_this_window();
        let excess_acked = self.ack_aggregation.update_ack_aggregation_bytes(
            bytes_acked,
            now,
            self.round_count,
            self.max_bandwidth.get_estimate(),
        );
        self.max_bandwidth.end_acks(self.round_count, app_limited);
        if let Some(largest_acked_packet) = largest_packet_num_acked {
            self.max_acked_packet_number = largest_acked_packet;
        }

        let mut is_round_start = false;
        if bytes_acked > 0 {
            is_round_start =
                self.max_acked_packet_number > self.current_round_trip_end_packet_number;
            if is_round_start {
                self.current_round_trip_end_packet_number = self.max_sent_packet_number;
                self.round_count += 1;
            }
        }

        self.update_recovery_state(is_round_start);

        if self.mode == Mode::ProbeBw {
            self.update_gain_cycle_phase(now, in_flight);
        }

        if is_round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bw_reached(app_limited);
        }

        self.maybe_exit_startup_or_drain(now, in_flight);

        self.maybe_enter_or_exit_probe_rtt(now, is_round_start, in_flight, app_limited);

        // After the model is updated, recalculate the pacing rate and congestion window.
        self.calculate_pacing_rate();
        self.calculate_cwnd(bytes_acked, excess_acked);
        self.calculate_recovery_window(bytes_acked, self.loss_state.lost_bytes, in_flight);

        self.prev_in_flight_count = in_flight;
        self.loss_state.reset();
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.loss_state.lost_bytes += lost_bytes;
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = u64::from(new_mtu);
        self.min_cwnd = calculate_min_window(self.current_mtu);
        self.init_cwnd = self.initial_window.max(self.min_cwnd);
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    fn window(&self) -> u64 {
        if self.mode == Mode::ProbeRtt {
            return self.get_probe_rtt_cwnd();
        } else if self.recovery_state.in_recovery() && self.mode != Mode::Startup {
            return self.cwnd.min(self.recovery_window);
        }
        self.cwnd
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut m = ControllerMetrics::default();
        m.congestion_window = self.window();
        m.ssthresh = None;
        m.pacing_rate = Some(self.pacing_rate * 8);
        m
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// A uniform value in `0..bound` from the operating system's generator. quinn draws this offset
/// from a `Pcg32` seeded from the OS; one draw per ProbeBw entry does not need a cached generator.
/// If the OS cannot supply randomness the offset is 0, a valid start of the gain cycle.
fn random_below(bound: u8) -> u8 {
    let bound = bound.max(1);
    // 256 is not a multiple of every bound: draws at or above `limit` are redrawn, so every
    // value is equally likely.
    let limit = 256 - 256 % u16::from(bound);
    loop {
        let mut byte = [0u8; 1];
        if getrandom::fill(&mut byte).is_err() {
            return 0;
        }
        if u16::from(byte[0]) < limit {
            return byte[0] % bound;
        }
    }
}

#[derive(Debug, Default, Copy, Clone)]
struct AckAggregationState {
    max_ack_height: MinMax,
    aggregation_epoch_start_time: Option<Instant>,
    aggregation_epoch_bytes: u64,
}

impl AckAggregationState {
    fn update_ack_aggregation_bytes(
        &mut self,
        newly_acked_bytes: u64,
        now: Instant,
        round: u64,
        max_bandwidth: u64,
    ) -> u64 {
        // Compute how many bytes are expected to be delivered, assuming max
        // bandwidth is correct.
        let expected_bytes_acked = max_bandwidth
            * now
                .saturating_duration_since(self.aggregation_epoch_start_time.unwrap_or(now))
                .as_micros() as u64
            / 1_000_000;

        // Reset the current aggregation epoch as soon as the ack arrival rate is
        // less than or equal to the max bandwidth.
        if self.aggregation_epoch_bytes <= expected_bytes_acked {
            // Reset to start measuring a new aggregation epoch.
            self.aggregation_epoch_bytes = newly_acked_bytes;
            self.aggregation_epoch_start_time = Some(now);
            return 0;
        }

        // Compute how many extra bytes were delivered vs max bandwidth.
        // Include the bytes most recently acknowledged to account for stretch acks.
        self.aggregation_epoch_bytes += newly_acked_bytes;
        let diff = self.aggregation_epoch_bytes - expected_bytes_acked;
        self.max_ack_height.update_max(round, diff);
        diff
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Mode {
    // Startup phase of the connection.
    Startup,
    // After achieving the highest possible bandwidth during the startup, lower
    // the pacing rate in order to drain the queue.
    Drain,
    // Cruising mode.
    ProbeBw,
    // Temporarily slow down sending in order to empty the buffer and measure
    // the real minimum RTT.
    ProbeRtt,
}

// Indicates how the congestion control limits the amount of bytes in flight.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RecoveryState {
    // Do not limit.
    NotInRecovery,
    // Allow an extra outstanding byte for each byte acknowledged.
    Conservation,
    // Allow two extra outstanding bytes for each byte acknowledged (slow
    // start).
    Growth,
}

impl RecoveryState {
    fn in_recovery(&self) -> bool {
        !matches!(self, Self::NotInRecovery)
    }
}

#[derive(Debug, Clone, Default)]
struct LossState {
    lost_bytes: u64,
}

impl LossState {
    fn reset(&mut self) {
        self.lost_bytes = 0;
    }

    fn has_losses(&self) -> bool {
        self.lost_bytes != 0
    }
}

fn calculate_min_window(current_mtu: u64) -> u64 {
    4 * current_mtu
}

// The gain used for the STARTUP, equal to 2/ln(2).
const K_DEFAULT_HIGH_GAIN: f32 = 2.885;
// The newly derived CWND gain for STARTUP, 2.
const K_DERIVED_HIGH_CWNDGAIN: f32 = 2.0;
// The cycle of gains used during the ProbeBw stage.
const K_PACING_GAIN: [f32; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

const K_STARTUP_GROWTH_TARGET: f32 = 1.25;
const K_ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP: u8 = 3;

// Do not allow initial congestion window to be greater than 200 packets.
const K_MAX_INITIAL_CONGESTION_WINDOW: u64 = 200;

const PROBE_RTT_BASED_ON_BDP: bool = true;
const DRAIN_TO_TARGET: bool = true;

// ---- Delivery-rate estimation (Vox's; replaces quinn's `bw_estimation.rs`) ----------------------
//
// quinn's estimator takes, per acknowledged packet, the smaller of the rate between the last two
// sends and the rate between the last two acknowledgements, and feeds the max filter only samples
// above its current maximum. Measured through the shipped binary on a 200 Mbit/s path with 1%
// loss, its estimate climbed past the link rate and, since a lower sample never enters the filter,
// never came down: the window it sized grew to eight bandwidth-delay products and filled the
// bottleneck's queue within a second of every entry to tier 3.
//
// This is the BBR draft's delivery-rate sampling instead (draft-cheng-iccrg-delivery-rate-
// estimation): each sent packet records how much had been delivered when it left, and when; its
// acknowledgement yields `delivered now - delivered then` over the longer of the send and the
// acknowledgement intervals, which an acknowledgement arriving bunched cannot shorten. Every sample
// goes to the max filter, which ages the old maximum out over its ten rounds as the draft's does.

/// The most sent-packet records kept: far more than any window holds in flight. If the
/// acknowledgements stop for long enough to pass it, the oldest records go and their packets, if
/// ever acknowledged, give no sample.
const MAX_SENT_RECORDS: usize = 1 << 16;

/// What the estimator remembers of one send.
#[derive(Clone, Copy, Debug)]
struct SentRecord {
    sent: Instant,
    /// Bytes delivered when it was sent…
    delivered: u64,
    /// …when the last of those was delivered…
    delivered_time: Instant,
    /// …and when the send interval it belongs to began.
    first_sent_time: Instant,
}

#[derive(Clone, Debug, Default)]
struct BandwidthEstimation {
    delivered: u64,
    delivered_time: Option<Instant>,
    first_sent_time: Option<Instant>,
    sent: VecDeque<SentRecord>,
    max_filter: MinMax,
    acked_at_last_window: u64,
}

impl BandwidthEstimation {
    fn on_sent(&mut self, now: Instant, _bytes: u64) {
        if self.sent.is_empty() {
            // Nothing in flight: the next sample's intervals start here.
            self.first_sent_time = Some(now);
            self.delivered_time = Some(now);
        }
        if self.sent.len() == MAX_SENT_RECORDS {
            self.sent.pop_front();
        }
        self.sent.push_back(SentRecord {
            sent: now,
            delivered: self.delivered,
            delivered_time: self.delivered_time.unwrap_or(now),
            first_sent_time: self.first_sent_time.unwrap_or(now),
        });
    }

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, round: u64, app_limited: bool) {
        self.delivered += bytes;
        self.delivered_time = Some(now);
        // Records are in send order. Those sent before this packet were acknowledged already, or
        // lost, or are acknowledged out of order and give no sample; they go.
        let at = self.sent.partition_point(|r| r.sent < sent);
        let record = self.sent.get(at).filter(|r| r.sent == sent).copied();
        self.sent.drain(..at);
        let Some(record) = record else {
            return;
        };
        // Several packets can share one send instant (one batch); keep the record for the rest.
        if self.sent.get(1).is_none_or(|next| next.sent != sent) {
            self.sent.pop_front();
        }
        self.first_sent_time = Some(record.sent);
        let send_elapsed = record
            .sent
            .saturating_duration_since(record.first_sent_time);
        let ack_elapsed = now.saturating_duration_since(record.delivered_time);
        let Some(rate) = Self::bw_from_delta(
            self.delivered - record.delivered,
            send_elapsed.max(ack_elapsed),
        ) else {
            return;
        };
        // An application-limited sample says less than the path can carry; it counts only when it
        // is the highest anyway.
        if !app_limited || rate >= self.max_filter.get() {
            self.max_filter.update_max(round, rate);
        }
    }

    fn bytes_acked_this_window(&self) -> u64 {
        self.delivered - self.acked_at_last_window
    }

    fn end_acks(&mut self, _current_round: u64, _app_limited: bool) {
        self.acked_at_last_window = self.delivered;
    }

    fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    const fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let window_duration_ns = delta.as_nanos();
        if window_duration_ns == 0 {
            return None;
        }
        let b_ns = bytes * 1_000_000_000;
        let bytes_per_second = b_ns / (window_duration_ns as u64);
        Some(bytes_per_second)
    }
}

// ---- quinn-proto 0.11.18 `congestion/bbr/min_max.rs` ---------------------------------------------

/*
 * Based on Google code released under BSD license here:
 * https://groups.google.com/forum/#!topic/bbr-dev/3RTgkzi5ZD8
 */

/*
 * Kathleen Nichols' algorithm for tracking the minimum (or maximum)
 * value of a data stream over some fixed time interval.  (E.g.,
 * the minimum RTT over the past five minutes.) It uses constant
 * space and constant time per update yet almost always delivers
 * the same minimum as an implementation that has to keep all the
 * data in the window.
 *
 * The algorithm keeps track of the best, 2nd best & 3rd best min
 * values, maintaining an invariant that the measurement time of
 * the n'th best >= n-1'th best. It also makes sure that the three
 * values are widely separated in the time window since that bounds
 * the worse case error when that data is monotonically increasing
 * over the window.
 *
 * Upon getting a new min, we can forget everything earlier because
 * it has no value - the new min is <= everything else in the window
 * by definition and it samples the most recent. So we restart fresh on
 * every new min and overwrites 2nd & 3rd choices. The same property
 * holds for 2nd & 3rd best.
 */

#[derive(Copy, Clone, Debug)]
struct MinMax {
    /// round count, not a timestamp
    window: u64,
    samples: [MinMaxSample; 3],
}

impl MinMax {
    fn get(&self) -> u64 {
        self.samples[0].value
    }

    fn fill(&mut self, sample: MinMaxSample) {
        self.samples.fill(sample);
    }

    fn reset(&mut self) {
        self.fill(Default::default())
    }

    /// update_min is also defined in the original source, but removed here since it is not used.
    fn update_max(&mut self, current_round: u64, measurement: u64) {
        let sample = MinMaxSample {
            time: current_round,
            value: measurement,
        };

        if self.samples[0].value == 0  /* uninitialised */
            || /* found new max? */ sample.value >= self.samples[0].value
            || /* nothing left in window? */ sample.time - self.samples[2].time > self.window
        {
            self.fill(sample); /* forget earlier samples */
            return;
        }

        if sample.value >= self.samples[1].value {
            self.samples[2] = sample;
            self.samples[1] = sample;
        } else if sample.value >= self.samples[2].value {
            self.samples[2] = sample;
        }

        self.subwin_update(sample);
    }

    /* As time advances, update the 1st, 2nd, and 3rd choices. */
    fn subwin_update(&mut self, sample: MinMaxSample) {
        let dt = sample.time - self.samples[0].time;
        if dt > self.window {
            /*
             * Passed entire window without a new sample so make 2nd
             * choice the new sample & 3rd choice the new 2nd choice.
             * we may have to iterate this since our 2nd choice
             * may also be outside the window (we checked on entry
             * that the third choice was in the window).
             */
            self.samples[0] = self.samples[1];
            self.samples[1] = self.samples[2];
            self.samples[2] = sample;
            if sample.time - self.samples[0].time > self.window {
                self.samples[0] = self.samples[1];
                self.samples[1] = self.samples[2];
                self.samples[2] = sample;
            }
        } else if self.samples[1].time == self.samples[0].time && dt > self.window / 4 {
            /*
             * We've passed a quarter of the window without a new sample
             * so take a 2nd choice from the 2nd quarter of the window.
             */
            self.samples[2] = sample;
            self.samples[1] = sample;
        } else if self.samples[2].time == self.samples[1].time && dt > self.window / 2 {
            /*
             * We've passed half the window without finding a new sample
             * so take a 3rd choice from the last half of the window
             */
            self.samples[2] = sample;
        }
    }
}

impl Default for MinMax {
    fn default() -> Self {
        Self {
            window: 10,
            samples: [Default::default(); 3],
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
struct MinMaxSample {
    /// round number, not a timestamp
    time: u64,
    value: u64,
}
