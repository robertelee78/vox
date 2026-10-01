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
//!
//! # Why a Vox Cubic, with HyStart++
//! quinn's Cubic leaves slow start only on loss. Each transfer starts in slow start (above), so on a
//! long path the window doubled until the queues overflowed: measured through the shipped binary
//! on GitHub's macOS runner, an emulated 1 Gbit/s, 50 ms path (bandwidth-delay product 6.25 MB)
//! saw the window reach 42-58 MB and the round trip climb to 110-240 ms, and the transfer then paid
//! for the burst of losses. R41 WAN on that runner: 61-106% of raw from one run to the next. The
//! kernels' own TCP (the raw arm) leaves slow start when the round trip rises (HyStart), and so
//! does this one now: `VoxCubic` is quinn 0.11's Cubic, ported unchanged outside slow start, with
//! HyStart++ (RFC 9406) deciding when slow start ends. quinn's `Controller` trait cannot end its
//! own Cubic's slow start from outside, which is why the Cubic is ours; quinn itself is untouched.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

/// How long a connection must have sent nothing before its next send starts from a fresh
/// controller. Long enough that the gaps inside one transfer (an application pausing between
/// writes, a request/response exchange) never trigger it; short enough that a new transfer
/// after a pause is treated as one.
pub const IDLE_RESTART: Duration = Duration::from_secs(1);

/// The idle period also has to span this many smoothed round trips, so a very long path is not
/// restarted between two flights of the same transfer.
const IDLE_RTTS: u32 = 4;

/// Builds `IdleRestart` controllers around `VoxCubic`.
#[derive(Debug, Default)]
pub struct IdleRestartConfig;

impl ControllerFactory for IdleRestartConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(IdleRestart {
            inner: Box::new(VoxCubic::new(now, current_mtu)),
            mtu: current_mtu,
            last_sent: None,
            srtt: Duration::ZERO,
        })
    }
}

/// Cubic, rebuilt from scratch when the connection goes idle. See the module docs.
struct IdleRestart {
    inner: Box<dyn Controller>,
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
            self.inner = Box::new(VoxCubic::new(now, self.mtu));
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

// ---- VoxCubic: quinn 0.11's Cubic with HyStart++ -----------------------------------------------
//
// The Cubic arithmetic below is quinn-proto 0.11.18's `congestion/cubic.rs` (MIT OR Apache-2.0),
// ported unchanged: RFC 8312's constants and equations, in bytes. What is Vox's is when slow start
// ends (HyStart++, RFC 9406, below).

/// RFC 8312 §5: the multiplicative decrease.
const BETA_CUBIC: f64 = 0.7;
/// ADR-024 tier 2: the cut for a loss that arrives with no queue behind it.
pub(crate) const BETA_LOSS_AWARE: f64 = 0.85;
/// RFC 8312 §5: the cubic scaling constant.
const C: f64 = 0.4;
/// quinn's default initial window: 14,720 bytes clamped to 2-10 base datagrams (1200 bytes).
const INITIAL_WINDOW: u64 = 12_000;

// RFC 9406 §4.3 recommended values.
/// The fewest round-trip samples in a round before a delay increase is judged.
const N_RTT_SAMPLE: u32 = 8;
/// The delay increase that ends slow start, as a share of the last round's minimum RTT…
const MIN_RTT_DIVISOR: u32 = 8;
/// …but never below this…
const MIN_RTT_THRESH: Duration = Duration::from_millis(4);
/// …nor above this.
const MAX_RTT_THRESH: Duration = Duration::from_millis(16);
/// Conservative Slow Start grows the window at this fraction of slow start's rate…
const CSS_GROWTH_DIVISOR: u64 = 4;
/// …for this many rounds, unless the delay falls back (a spurious exit).
const CSS_ROUNDS: u32 = 5;

/// Where HyStart++ has the connection: slow start, Conservative Slow Start, or done (congestion
/// avoidance, which is Cubic's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    SlowStart,
    Css { baseline: Duration, rounds: u32 },
    Done,
}

/// Cubic's state across the connection (RFC 8312 §4).
#[derive(Debug, Default, Clone)]
struct CubicState {
    k: f64,
    w_max: f64,
    cwnd_inc: u64,
}

impl CubicState {
    // K = cbrt(w_max * (1 - beta) / C)  (RFC 8312 Eq. 2)
    fn cubic_k(&self, mtu: u64, beta: f64) -> f64 {
        let w_max = self.w_max / mtu as f64;
        (w_max * (1.0 - beta) / C).cbrt()
    }
    // W_cubic(t) = C * (t - K)^3 + w_max  (Eq. 1)
    fn w_cubic(&self, t: Duration, mtu: u64) -> f64 {
        let w_max = self.w_max / mtu as f64;
        (C * (t.as_secs_f64() - self.k).powi(3) + w_max) * mtu as f64
    }
    // W_est(t) = w_max * beta + 3 * (1 - beta) / (1 + beta) * (t / RTT)  (Eq. 4)
    fn w_est(&self, t: Duration, rtt: Duration, mtu: u64) -> f64 {
        let w_max = self.w_max / mtu as f64;
        (w_max * BETA_CUBIC
            + 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC) * t.as_secs_f64() / rtt.as_secs_f64())
            * mtu as f64
    }
}

/// quinn's Cubic, with slow start ended by HyStart++ (RFC 9406) as well as by loss.
///
/// Rounds are counted in packet numbers: a round ends when a packet sent after it began is
/// acknowledged. Each acknowledgement's round-trip sample is its own `now - sent`. Once a round has
/// [`N_RTT_SAMPLE`] samples and its minimum exceeds the previous round's by the threshold, slow
/// start gives way to Conservative Slow Start (a quarter of the growth). A later round whose
/// minimum is back under the baseline was a false alarm, and slow start resumes; after
/// [`CSS_ROUNDS`] rounds without that, the window becomes the slow-start threshold and Cubic's
/// congestion avoidance takes over. Loss in either phase is Cubic's ordinary reduction. quinn
/// paces, so RFC 9406's burst limit `L` is unlimited.
#[derive(Debug, Clone)]
pub(crate) struct VoxCubic {
    window: u64,
    ssthresh: u64,
    recovery_start_time: Option<Instant>,
    state: CubicState,
    mtu: u64,
    phase: Phase,
    last_sent_pn: u64,
    round_end_pn: Option<u64>,
    last_round_min: Option<Duration>,
    round_min: Option<Duration>,
    round_samples: u32,
    loss_aware: bool,
}

impl VoxCubic {
    pub(crate) fn new(_now: Instant, current_mtu: u16) -> Self {
        Self {
            window: INITIAL_WINDOW,
            ssthresh: u64::MAX,
            recovery_start_time: None,
            state: CubicState::default(),
            mtu: u64::from(current_mtu),
            phase: Phase::SlowStart,
            last_sent_pn: 0,
            round_end_pn: None,
            last_round_min: None,
            round_min: None,
            round_samples: 0,
            loss_aware: false,
        }
    }

    /// A Cubic already in congestion avoidance at `window`, as if it had just grown there: the
    /// hand-off when the taper leaves BBR (ADR-024 rule 5), so stepping down does not cost a slow
    /// start. `last_sent_pn` lets its rounds continue from the connection's packet numbers.
    pub(crate) fn seeded(now: Instant, current_mtu: u16, last_sent_pn: u64, window: u64) -> Self {
        let mut c = Self::new(now, current_mtu);
        c.window = window.max(c.minimum_window());
        c.ssthresh = c.window;
        c.state.w_max = c.window as f64;
        c.phase = Phase::Done;
        c.last_sent_pn = last_sent_pn;
        c
    }

    /// Tier 2 on or off (ADR-024): when on, a loss that [`PathSignals`] does not call congestion
    /// takes the gentle [`BETA_LOSS_AWARE`] cut instead of Cubic's.
    pub(crate) fn set_loss_aware(&mut self, on: bool) {
        self.loss_aware = on;
    }

    /// A loss, already classified: `congestion` is [`PathSignals::loss_is_congestion`]. Cubic's
    /// full cut for congestion, for persistent congestion, for an ECN mark (`lost_bytes == 0`), and
    /// whenever tier 2 is off; the gentle cut otherwise.
    pub(crate) fn on_loss(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
        congestion: bool,
    ) {
        let gentle = self.loss_aware && !congestion && !is_persistent_congestion && lost_bytes > 0;
        let beta = if gentle { BETA_LOSS_AWARE } else { BETA_CUBIC };
        self.cut(now, sent, is_persistent_congestion, beta);
    }

    /// Cubic's multiplicative decrease with `beta` (RFC 8312 §4.5-4.6), once per recovery period.
    fn cut(&mut self, now: Instant, sent: Instant, is_persistent_congestion: bool, beta: f64) {
        if self
            .recovery_start_time
            .is_some_and(|recovery_start_time| sent <= recovery_start_time)
        {
            return;
        }
        // Loss ends HyStart++ whatever its phase: from here it is Cubic's.
        self.phase = Phase::Done;
        self.recovery_start_time = Some(now);
        let window = self.window as f64;
        self.state.w_max = if window < self.state.w_max {
            window * (1.0 + beta) / 2.0
        } else {
            window
        };
        self.ssthresh = ((window * beta) as u64).max(self.minimum_window());
        self.window = self.ssthresh;
        self.state.k = self.state.cubic_k(self.mtu, beta);
        self.state.cwnd_inc = (self.state.cwnd_inc as f64 * beta) as u64;
        if is_persistent_congestion {
            self.recovery_start_time = None;
            self.state.w_max = self.window as f64;
            self.ssthresh = ((self.window as f64 * BETA_CUBIC) as u64).max(self.minimum_window());
            self.state.cwnd_inc = 0;
            self.window = self.minimum_window();
        }
    }

    fn minimum_window(&self) -> u64 {
        2 * self.mtu
    }

    /// RFC 9406 §4.2: the delay rise that ends slow start, from the last round's minimum RTT.
    fn rtt_thresh(last_round_min: Duration) -> Duration {
        (last_round_min / MIN_RTT_DIVISOR).clamp(MIN_RTT_THRESH, MAX_RTT_THRESH)
    }

    /// A round has ended: roll the minimums, and move Conservative Slow Start on a round.
    fn end_round(&mut self) {
        if let Phase::Css { baseline, rounds } = self.phase {
            let rounds = rounds + 1;
            if rounds >= CSS_ROUNDS {
                // RFC 9406 §4.2: CSS confirmed; congestion avoidance from here.
                self.ssthresh = self.window;
                self.phase = Phase::Done;
            } else {
                self.phase = Phase::Css { baseline, rounds };
            }
        }
        self.last_round_min = self.round_min.or(self.last_round_min);
        self.round_min = None;
        self.round_samples = 0;
        self.round_end_pn = Some(self.last_sent_pn);
    }

    /// One round-trip sample while the window is below the slow-start threshold.
    fn hystart_sample(&mut self, sample: Duration) {
        self.round_min = Some(self.round_min.map_or(sample, |m| m.min(sample)));
        self.round_samples = self.round_samples.saturating_add(1);
        if self.round_samples < N_RTT_SAMPLE {
            return;
        }
        let (Some(current), Some(last)) = (self.round_min, self.last_round_min) else {
            return;
        };
        match self.phase {
            Phase::SlowStart if current >= last + Self::rtt_thresh(last) => {
                self.phase = Phase::Css {
                    baseline: current,
                    rounds: 0,
                };
            }
            Phase::Css { baseline, .. } if current < baseline => {
                // RFC 9406 §4.2: the rise was spurious; back to slow start.
                self.phase = Phase::SlowStart;
            }
            _ => {}
        }
    }
}

impl Controller for VoxCubic {
    fn on_sent(&mut self, _now: Instant, _bytes: u64, last_packet_number: u64) {
        self.last_sent_pn = last_packet_number;
        if self.round_end_pn.is_none() {
            self.round_end_pn = Some(last_packet_number);
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if app_limited
            || self
                .recovery_start_time
                .is_some_and(|recovery_start_time| sent <= recovery_start_time)
        {
            return;
        }

        if self.window < self.ssthresh {
            if self.phase != Phase::Done {
                self.hystart_sample(now.saturating_duration_since(sent));
            }
            // Slow start, or a quarter of it in Conservative Slow Start (RFC 9406 §4.2).
            self.window += match self.phase {
                Phase::Css { .. } => bytes / CSS_GROWTH_DIVISOR,
                _ => bytes,
            };
        } else {
            let ca_start_time = match self.recovery_start_time {
                Some(t) => t,
                None => {
                    self.recovery_start_time = Some(now);
                    self.state.w_max = self.window as f64;
                    self.state.k = 0.0;
                    now
                }
            };
            let t = now - ca_start_time;
            let w_cubic = self.state.w_cubic(t + rtt.get(), self.mtu);
            let w_est = self.state.w_est(t, rtt.get(), self.mtu);
            let mut cubic_cwnd = self.window;
            if w_cubic < w_est {
                cubic_cwnd = cubic_cwnd.max(w_est as u64);
            } else if cubic_cwnd < w_cubic as u64 {
                let cubic_inc = (w_cubic - cubic_cwnd as f64) / cubic_cwnd as f64 * self.mtu as f64;
                cubic_cwnd = cubic_cwnd.saturating_add(cubic_inc as u64);
            }
            self.state.cwnd_inc += cubic_cwnd - self.window;
            if self.state.cwnd_inc >= self.mtu {
                self.window += self.mtu;
                self.state.cwnd_inc = 0;
            }
        }
    }

    fn on_end_acks(
        &mut self,
        _now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        if let (Some(acked), Some(end)) = (largest_packet_num_acked, self.round_end_pn) {
            if acked >= end {
                self.end_round();
            }
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        self.cut(now, sent, is_persistent_congestion, BETA_CUBIC);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu);
        self.window = self.window.max(self.minimum_window());
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut m = ControllerMetrics::default();
        m.congestion_window = self.window;
        m.ssthresh = Some(self.ssthresh);
        m
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

// ---- PathSignals: what the path is doing, for every tier of the taper (ADR-024) -----------------

/// How long the path's base round trip is remembered. A path changes (a tunnel's connection outlives
/// the network it started on), so the base is the minimum of the samples of this window, never the
/// connection's lifetime minimum: quinn's `RttEstimator::min` is lifetime, and on a connection that
/// first ran over a faster path it reads that path's round trip for as long as the connection lives.
pub(crate) const BASE_RTT_WINDOW: Duration = Duration::from_secs(10);
/// A queue is building when a round's minimum round trip exceeds the base by this much…
pub(crate) const QUEUE_DELAY_MIN: Duration = Duration::from_millis(2);
/// …or by this share of the base, whichever is larger.
pub(crate) const QUEUE_DELAY_SHARE: f64 = 0.25;
/// Losses that tier 2 treats gently may not exceed this share of the packets sent over the last
/// [`LOSS_ROUNDS`]; past it, a loss is congestion whatever the delay says (a policer, or a queue
/// too shallow to show as delay).
pub(crate) const GENTLE_LOSS_CAP: f64 = 0.05;
/// How many recent rounds the loss counts cover.
pub(crate) const LOSS_ROUNDS: usize = 8;
/// How long the best delivery rate is remembered.
pub(crate) const BEST_RATE_WINDOW: Duration = Duration::from_secs(10);

/// One finished round: packets the controller saw sent and lost in it, and whether a queue showed.
#[derive(Debug, Clone, Copy, Default)]
struct RoundLoss {
    sent: u64,
    lost: u64,
    gentle_losses: u32,
    queued_losses: u32,
}

/// The path, as every tier sees it: a windowed base round trip, each round's minimum round trip,
/// delivery rate per round, the best rate of the last [`BEST_RATE_WINDOW`], and recent losses with
/// and without a queue. Rounds are counted in packet numbers, as HyStart++'s are: a round ends when a
/// packet sent after it began is acknowledged. Each acknowledgement's sample is its own `now - sent`.
#[derive(Debug, Clone)]
pub(crate) struct PathSignals {
    /// Monotonic deque of (when, sample): the front is the base round trip.
    base: std::collections::VecDeque<(Instant, Duration)>,
    /// Monotonic deque of (when, rate): the front is the best rate.
    best: std::collections::VecDeque<(Instant, u64)>,
    srtt: Duration,
    last_sent_pn: u64,
    round_end_pn: Option<u64>,
    round_start: Option<Instant>,
    round_min: Option<Duration>,
    round_acked: u64,
    round_sent: u64,
    round_lost: u64,
    round_gentle: u32,
    round_queued: u32,
    last_round_min: Option<Duration>,
    last_rate: u64,
    last_app_limited: bool,
    rounds: u64,
    recent: std::collections::VecDeque<RoundLoss>,
}

impl Default for PathSignals {
    fn default() -> Self {
        Self::new()
    }
}

impl PathSignals {
    pub(crate) fn new() -> Self {
        Self {
            base: std::collections::VecDeque::new(),
            best: std::collections::VecDeque::new(),
            srtt: Duration::ZERO,
            last_sent_pn: 0,
            round_end_pn: None,
            round_start: None,
            round_min: None,
            round_acked: 0,
            round_sent: 0,
            round_lost: 0,
            round_gentle: 0,
            round_queued: 0,
            last_round_min: None,
            last_rate: 0,
            last_app_limited: false,
            rounds: 0,
            recent: std::collections::VecDeque::with_capacity(LOSS_ROUNDS + 1),
        }
    }

    pub(crate) fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.last_sent_pn = last_packet_number;
        self.round_sent += bytes;
        if self.round_end_pn.is_none() {
            self.round_end_pn = Some(last_packet_number);
            self.round_start = Some(now);
        }
    }

    pub(crate) fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.srtt = rtt.get();
        let sample = now.saturating_duration_since(sent);
        while self.base.back().is_some_and(|&(_, m)| m >= sample) {
            self.base.pop_back();
        }
        self.base.push_back((now, sample));
        while self
            .base
            .front()
            .is_some_and(|&(t, _)| now.saturating_duration_since(t) > BASE_RTT_WINDOW)
        {
            self.base.pop_front();
        }
        self.round_min = Some(self.round_min.map_or(sample, |m| m.min(sample)));
        self.round_acked += bytes;
    }

    pub(crate) fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        app_limited: bool,
        largest: Option<u64>,
    ) {
        let (Some(acked), Some(end)) = (largest, self.round_end_pn) else {
            return;
        };
        if acked < end {
            return;
        }
        // A round has ended.
        let elapsed = self
            .round_start
            .map_or(Duration::ZERO, |t| now.saturating_duration_since(t));
        if !elapsed.is_zero() {
            self.last_rate = (self.round_acked as f64 / elapsed.as_secs_f64()) as u64;
            // An application-limited round says what the application offered, not what the path
            // carries, so it never sets the best rate.
            if !app_limited {
                while self.best.back().is_some_and(|&(_, r)| r <= self.last_rate) {
                    self.best.pop_back();
                }
                self.best.push_back((now, self.last_rate));
            }
        }
        while self
            .best
            .front()
            .is_some_and(|&(t, _)| now.saturating_duration_since(t) > BEST_RATE_WINDOW)
        {
            self.best.pop_front();
        }
        self.last_app_limited = app_limited;
        self.last_round_min = self.round_min.or(self.last_round_min);
        self.recent.push_back(RoundLoss {
            sent: self.round_sent,
            lost: self.round_lost,
            gentle_losses: self.round_gentle,
            queued_losses: self.round_queued,
        });
        while self.recent.len() > LOSS_ROUNDS {
            self.recent.pop_front();
        }
        self.rounds += 1;
        self.round_min = None;
        self.round_acked = 0;
        self.round_sent = 0;
        self.round_lost = 0;
        self.round_gentle = 0;
        self.round_queued = 0;
        self.round_start = Some(now);
        self.round_end_pn = Some(self.last_sent_pn);
    }

    /// Record a loss and say whether it is congestion: persistent congestion, an ECN mark
    /// (`lost_bytes == 0`), a queue building, or losses over the last [`LOSS_ROUNDS`] already past
    /// [`GENTLE_LOSS_CAP`] of what was sent. Pass the answer to [`VoxCubic::on_loss`].
    pub(crate) fn on_loss(&mut self, _now: Instant, lost_bytes: u64, persistent: bool) -> bool {
        self.round_lost += lost_bytes;
        let congestion = persistent
            || lost_bytes == 0
            || self.queue_building()
            || self.loss_share() > GENTLE_LOSS_CAP;
        if congestion {
            self.round_queued += 1;
        } else {
            self.round_gentle += 1;
        }
        congestion
    }

    /// The base round trip: the smallest sample of the last [`BASE_RTT_WINDOW`].
    pub(crate) fn min_rtt(&self) -> Option<Duration> {
        self.base.front().map(|&(_, m)| m)
    }

    pub(crate) fn srtt(&self) -> Duration {
        self.srtt
    }

    /// Is a queue building? The last finished round's minimum round trip stands above the base by
    /// at least [`QUEUE_DELAY_MIN`] or [`QUEUE_DELAY_SHARE`] of it, whichever is larger. A round's
    /// minimum, not its smoothed round trip: one delayed acknowledgement must not read as a queue.
    pub(crate) fn queue_building(&self) -> bool {
        let (Some(base), Some(round)) = (self.min_rtt(), self.last_round_min) else {
            return false;
        };
        let rise = round.saturating_sub(base);
        rise >= QUEUE_DELAY_MIN.max(base.mul_f64(QUEUE_DELAY_SHARE))
    }

    /// Bytes per second delivered over the last finished round.
    pub(crate) fn delivery_rate(&self) -> u64 {
        self.last_rate
    }

    /// The best delivery rate of the last [`BEST_RATE_WINDOW`], application-limited rounds excluded.
    pub(crate) fn best_rate(&self, _now: Instant) -> u64 {
        self.best.front().map_or(0, |&(_, r)| r)
    }

    pub(crate) fn rounds(&self) -> u64 {
        self.rounds
    }

    /// Was the last finished round application-limited? Such a round is no evidence about the path.
    pub(crate) fn app_limited(&self) -> bool {
        self.last_app_limited
    }

    /// The largest packet number sent so far: a controller handed the connection continues its
    /// rounds from here.
    pub(crate) fn last_sent_pn(&self) -> u64 {
        self.last_sent_pn
    }

    /// Did a loss in the current or last finished round come with a queue (or past the cap)?
    pub(crate) fn loss_with_queue(&self) -> bool {
        self.round_queued > 0 || self.recent.back().is_some_and(|r| r.queued_losses > 0)
    }

    /// Losses without a queue, over the last `rounds` finished rounds.
    pub(crate) fn losses_without_queue_in_last(&self, rounds: usize) -> u32 {
        self.recent.iter().rev().take(rounds).map(|r| r.gentle_losses).sum()
    }

    /// Losses that came with a queue (or past the cap), over the last `rounds` finished rounds.
    pub(crate) fn losses_with_queue_in_last(&self, rounds: usize) -> u32 {
        self.recent.iter().rev().take(rounds).map(|r| r.queued_losses).sum()
    }

    /// Bytes lost over bytes sent, across the last [`LOSS_ROUNDS`] finished rounds and this one.
    pub(crate) fn loss_share(&self) -> f64 {
        let (sent, lost) = self
            .recent
            .iter()
            .fold((self.round_sent, self.round_lost), |(s, l), r| (s + r.sent, l + r.lost));
        if sent == 0 {
            0.0
        } else {
            lost as f64 / sent as f64
        }
    }
}
