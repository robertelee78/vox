//! The tapered congestion controller's tier switch (ADR-024, M24.4).
//!
//! # Tiers
//! | Tier | Controller |
//! |---|---|
//! | 1 | [`VoxCubic`]: every loss is congestion |
//! | 2 | [`VoxCubic`], loss-aware: a loss [`PathSignals`] does not judge congestion takes no cut (M24.3) |
//! | 3 | [`VoxBbr`]: quinn's BBR, owned by Vox |
//!
//! Every connection starts in tier 1 and moves **one tier at a time, both ways** (ADR-024 rules 1
//! and 2). The decisions here read [`PathSignals`], which measures the path from the controller
//! callbacks whichever tier is running, so a tier is never judged by its own model.
//!
//! # Decisions, evaluated once per round trip
//! - **Climb 1 → 2** when the last [`CLIMB_1_ROUNDS`] rounds held at least [`CLIMB_1_LOSSES`]
//!   losses with no queue building, once tier 1's dwell is over, and the loss share over the last
//!   32 MiB is at least [`TIER2_ENTRY_SHARE`]. That share is marked as tier 2's baseline, which
//!   follows the trend up until tier 2 has sent 32 MiB of its own: loss that then grows with Vox's
//!   own sending is congestion.
//! - **Climb 2 → 3** when the loss share over the last 32 MiB sent (`PathSignals::trend_share`)
//!   is at or above [`GENTLE_LOSS_CAP`], past which tier 2 cuts for every loss, and no queue has
//!   been held for [`CLIMB_3_QUEUE_ROUNDS`] rounds in a row in the last [`CLIMB_3_ROUNDS`] rounds and
//!   [`CLIMB_3_TIME`]. Not the share over the last few rounds: at 8 KB datagrams eight rounds
//!   hold a couple of hundred packets, and on a link losing 5% at random that share read 0–14%
//!   from one half-second to the next, so a streak of rounds at the cap never reached 20 and tier 3
//!   was never entered (measured: 1.42x and 1.62x a Cubic flow, against BBR's 7.68x). Nor a
//!   queue of a round or two: one round in the trace read 39 ms on a 10.6 ms base with nothing
//!   else on the path, and see [`CLIMB_3_QUEUE_ROUNDS`]. **The loss share is the clean-LAN guard:** a clean link loses only when its
//!   queue overflows, well under 1% of what it sends, so it never reaches BBR.
//! - **Leave tier 3 when it is slower than tier 2 was.** ADR-024 guarantees speed only (the
//!   decider, 2026-10-02): tier 3 exists to be faster, and is kept only while it is. Vox's
//!   delivered rate over the last [`RATE_WINDOW`] is recorded at 2 → 3; once tier 3 has dwelt, a
//!   round whose rate over the same window is under [`TIER3_SLOWER`] of it takes the connection
//!   back to tier 2 and locks tier 3 out for a back-off: [`BACKOFF_FIRST`], doubling with each
//!   such exit up to [`BACKOFF_MAX`], and back to the first only after a tier-3 stay of
//!   [`BACKOFF_RESET`] without one. Earlier candidates also left tier 3 on a queue another flow
//!   built (rule 3), on a loss share that rose with Vox's rate (the trial), and on an ECN mark or
//!   persistent congestion: those protected other flows, fairness is not ADR-024's to guarantee,
//!   and they are gone.
//! - **Descend 3 → 2 when the loss is gone:** the loss share under half [`GENTLE_LOSS_CAP`] for
//!   [`QUIET_ROUNDS`] rounds and [`QUIET_TIME`].
//! - **Descend 2 → 1** after a quiet stretch: [`QUIET_ROUNDS`] consecutive rounds and
//!   [`QUIET_TIME`] with no loss and no queue. Tier 2's loss baseline is cleared. Not on the rate
//!   holding up as well: a rate measured on this connection cannot tell a path that got worse from
//!   an application that sent less, or from an earlier, faster path within the window.
//! - **Hysteresis and dwell.** Each climb and its descent test different things, and a descent
//!   needs a longer stretch than a climb. Every tier is left no sooner than [`DWELL_ROUNDS`]
//!   rounds and [`DWELL_TIME`].
//!
//! An application-limited round is no evidence either way.
//!
//! # Hand-off (rule 5)
//! A switch hands the connection's rate on, so it never pays slow start again:
//! - **into BBR**: [`VoxBbr::seeded`] with the rate tier 2 was sending at (its window over the
//!   smoothed round trip), the base round trip and the current window, in ProbeBw, never Startup.
//!   Not the best rate: a round closed on bunched acknowledgements once read 6.4 Gbit/s on a
//!   200 Mbit/s link, and BBR seeded with it filled the buffer in its first round. BBR's own
//!   delivery-rate samples raise a low seed within a few rounds. Never Startup: its 2.885 gain
//!   overshoots a path whose capacity tier 2 has already shown;
//! - **out of BBR**: [`VoxCubic::seeded`] in congestion avoidance at BBR's delivery rate times the
//!   windowed minimum round trip.
//!
//! # Idle restart
//! `IdleRestart` (congestion.rs) rebuilds this controller after the connection has sent nothing
//! for a while: the tier goes back to 1 and the base round trip is measured afresh, because the
//! path may have changed. The tier-3 lockout is handed on ([`Tier3Backoff`]): a tier 3 that was
//! slower stays locked out across a pause.
//!
//! # Troubleshooting
//! Each switch emits `tracing::debug!` under the target `vox::congestion`, with the tiers, the
//! reason and the signal that decided it. Nothing prints by default.

use std::any::Any;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerMetrics};
use quinn_proto::RttEstimator;

use super::congestion::{PathSignals, VoxCubic, GENTLE_LOSS_CAP, TREND_BYTES};
use super::vox_bbr::{RateSeed, VoxBbr};

/// The rounds a climb from tier 1 looks back over…
pub(crate) const CLIMB_1_ROUNDS: usize = 8;
/// …and the losses with no queue building it needs in them.
pub(crate) const CLIMB_1_LOSSES: u32 = 3;
/// The loss share over the last 32 MiB a climb from tier 1 also needs. Tier 2's loss baseline is
/// that same share, so tier 2 starts from the loss that made it, never from clean history: a
/// link that turned lossy mid-transfer otherwise entered tier 2 with a baseline of 0.1%, and 1%
/// random loss then read as risen, so tier 2 cut like Cubic (measured: 57 Mbit/s through a 1%
/// phase that tier 2 carries at about 180). A clean link's overflow losses, about 0.1%, never
/// reach it.
pub(crate) const TIER2_ENTRY_SHARE: f64 = 0.005;
/// Consecutive rounds without a held queue for a climb from tier 2…
pub(crate) const CLIMB_3_ROUNDS: u32 = 20;
/// …spanning at least this long; a queue is held when it shows for this many rounds in a row.
pub(crate) const CLIMB_3_TIME: Duration = Duration::from_secs(2);
/// The rounds in a row a queue must show to break a climb from tier 2. Not one or two: on a lossy
/// link tier 2 sends little, and at 8 KB datagrams a round then holds one to four packets, so one
/// delayed acknowledgement lifts a round's minimum round trip past the queue test. Measured on the
/// 5% arm with nothing else on the path: rounds 4–7 ms over the base, two in a row about once a
/// second, which broke every 2-second streak and kept tier 3 out (1.25x a Cubic flow).
pub(crate) const CLIMB_3_QUEUE_ROUNDS: u32 = 8;
/// The window Vox's delivered rate is measured over, for tier 3's speed check.
pub(crate) const RATE_WINDOW: Duration = Duration::from_secs(2);
/// The delivered-rate meter keeps one point per this much time, not one per acknowledged packet,
/// so it holds at most [`RATE_WINDOW`] / this many points however fast the link is.
pub(crate) const RATE_POINT: Duration = Duration::from_millis(10);
/// Tier 3 is left when its delivered rate falls under this share of tier 2's at the switch.
pub(crate) const TIER3_SLOWER: f64 = 0.9;
/// Tier 3 is locked out this long after a first exit for being slower…
pub(crate) const BACKOFF_FIRST: Duration = Duration::from_secs(30);
/// …doubling with each further one, up to this…
pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(480);
/// …and back to the first after a tier-3 stay this long without one.
pub(crate) const BACKOFF_RESET: Duration = Duration::from_secs(300);
/// Consecutive rounds of a stretch that descends a tier…
pub(crate) const QUIET_ROUNDS: u32 = 40;
/// …spanning at least this long.
pub(crate) const QUIET_TIME: Duration = Duration::from_secs(4);
/// The fewest rounds every tier runs before it may be left…
pub(crate) const DWELL_ROUNDS: u32 = 20;
/// …and the least time.
pub(crate) const DWELL_TIME: Duration = Duration::from_secs(2);

/// Which tier a connection is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TierId {
    One,
    Two,
    Three,
}

impl TierId {
    fn number(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
        }
    }
}

#[derive(Debug, Clone)]
enum Tier {
    Cubic(VoxCubic),
    Bbr(Box<VoxBbr>),
}

impl Tier {
    fn controller(&self) -> &dyn Controller {
        match self {
            Self::Cubic(c) => c,
            Self::Bbr(b) => b.as_ref(),
        }
    }
    fn controller_mut(&mut self) -> &mut dyn Controller {
        match self {
            Self::Cubic(c) => c,
            Self::Bbr(b) => b.as_mut(),
        }
    }
}

/// A run of consecutive rounds that meet a test, and when it began.
#[derive(Debug, Clone, Copy, Default)]
struct Streak {
    rounds: u32,
    since: Option<Instant>,
}

impl Streak {
    fn update(&mut self, now: Instant, holds: bool) {
        if holds {
            self.rounds = self.rounds.saturating_add(1);
            self.since.get_or_insert(now);
        } else {
            *self = Self::default();
        }
    }
    fn reset(&mut self) {
        *self = Self::default();
    }
    /// Has it held for `rounds` rounds and `time`?
    fn held(&self, now: Instant, rounds: u32, time: Duration) -> bool {
        self.rounds >= rounds
            && self
                .since
                .is_some_and(|t| now.saturating_duration_since(t) >= time)
    }
}

/// Tier 3's lockout after exits for being slower. It outlives the controller: `IdleRestart` rebuilds the
/// connection's controller at tier 1 after an idle period, with a fresh base round trip, because the
/// path may have changed; but it hands this on ([`Tapered::tier3_backoff`],
/// [`Tapered::with_tier3_backoff`]), so a sender that pauses does not earn a retry of a tier 3 that
/// was slower.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Tier3Backoff {
    /// The lockout the next failure imposes ([`BACKOFF_FIRST`] when `None`).
    next: Option<Duration>,
    until: Option<Instant>,
}

impl Tier3Backoff {
    fn locked(&self, now: Instant) -> bool {
        self.until.is_some_and(|t| now < t)
    }
    fn fail(&mut self, now: Instant) {
        let lockout = self.next.unwrap_or(BACKOFF_FIRST);
        self.until = Some(now + lockout);
        self.next = Some((lockout * 2).min(BACKOFF_MAX));
    }
    /// A tier-3 stay of [`BACKOFF_RESET`] without a failure: the next lockout is the first again.
    fn forgive(&mut self) {
        self.next = None;
    }
}

/// The tapered controller: one of three tiers, and the switch between them.
#[derive(Debug, Clone)]
pub(crate) struct Tapered {
    tier_id: TierId,
    tier: Tier,
    signals: PathSignals,
    mtu: u16,
    entered_at: Instant,
    rounds_in_tier: u32,
    /// Vox's delivered rate at 2 -> 3, bytes per second.
    tier3_entry_rate: f64,
    /// (time, bytes acknowledged so far) over the last [`RATE_WINDOW`], oldest first, one point per
    /// [`RATE_POINT`].
    acked: std::collections::VecDeque<(Instant, u64)>,
    acked_total: u64,
    /// Tier 2's loss baseline while it settles: bytes sent since 1 -> 2, and the baseline marked.
    tier2_sent: u64,
    tier2_baseline: Option<f64>,
    backoff: Tier3Backoff,
    /// Rounds without a held queue, toward a climb from tier 2.
    unqueued: Streak,
    /// Rounds in a row that showed a queue (any tier but 3).
    queued: Streak,
    quiet: Streak,
    loss_gone: Streak,
}

impl Tapered {
    /// A connection's controller: tier 1, Cubic in slow start.
    pub(crate) fn new(now: Instant, current_mtu: u16) -> Self {
        Self {
            tier_id: TierId::One,
            tier: Tier::Cubic(VoxCubic::new(now, current_mtu)),
            signals: PathSignals::new(),
            mtu: current_mtu,
            entered_at: now,
            rounds_in_tier: 0,
            tier3_entry_rate: 0.0,
            acked: std::collections::VecDeque::new(),
            acked_total: 0,
            tier2_sent: 0,
            tier2_baseline: None,
            backoff: Tier3Backoff::default(),
            unqueued: Streak::default(),
            queued: Streak::default(),
            quiet: Streak::default(),
            loss_gone: Streak::default(),
        }
    }

    /// A connection's controller after an idle restart: tier 1, Cubic in slow start, a fresh base
    /// round trip, and the tier-3 lockout the previous controller had built up.
    pub(crate) fn with_tier3_backoff(
        now: Instant,
        current_mtu: u16,
        backoff: Tier3Backoff,
    ) -> Self {
        let mut tapered = Self::new(now, current_mtu);
        tapered.backoff = backoff;
        tapered
    }

    /// The tier-3 lockout, for an idle restart to hand on.
    pub(crate) fn tier3_backoff(&self) -> Tier3Backoff {
        self.backoff
    }

    /// Vox's delivered rate over the last [`RATE_WINDOW`] (or what there is of it), bytes per
    /// second: acknowledged bytes, which is what reached the peer.
    fn delivered_rate(&self, now: Instant) -> f64 {
        let Some(&(since, at)) = self.acked.front() else {
            return 0.0;
        };
        let span = now.saturating_duration_since(since).as_secs_f64();
        if span <= 0.0 {
            0.0
        } else {
            (self.acked_total - at) as f64 / span
        }
    }

    /// One round has finished: update the streaks, and switch tier if they say so.
    fn on_round(&mut self, now: Instant) {
        self.rounds_in_tier = self.rounds_in_tier.saturating_add(1);
        let in_tier = now.saturating_duration_since(self.entered_at);
        if self.tier_id == TierId::Three && in_tier >= BACKOFF_RESET {
            self.backoff.forgive();
        }
        if self.signals.app_limited() {
            return;
        }
        self.settle_tier2_baseline();
        let share = self.signals.loss_share();
        let queued = self.signals.queue_building();
        let lossy =
            self.signals.losses_without_queue_in_last(1) > 0 || self.signals.loss_with_queue();

        self.queued.update(now, queued);
        self.unqueued
            .update(now, self.queued.rounds < CLIMB_3_QUEUE_ROUNDS);
        self.quiet.update(now, !queued && !lossy);
        self.loss_gone.update(now, share < GENTLE_LOSS_CAP / 2.0);

        let dwelt = self.rounds_in_tier >= DWELL_ROUNDS && in_tier >= DWELL_TIME;
        let decision = match self.tier_id {
            TierId::Three
                if dwelt && self.delivered_rate(now) < TIER3_SLOWER * self.tier3_entry_rate =>
            {
                Some((TierId::Two, "tier 3 is slower than tier 2 was", true))
            }
            TierId::Three if dwelt && self.loss_gone.held(now, QUIET_ROUNDS, QUIET_TIME) => {
                Some((TierId::Two, "the loss is gone", false))
            }
            TierId::One
                if dwelt
                    && self.signals.losses_without_queue_in_last(CLIMB_1_ROUNDS)
                        >= CLIMB_1_LOSSES
                    && self.signals.trend_share() >= TIER2_ENTRY_SHARE =>
            {
                Some((TierId::Two, "loss without a queue", false))
            }
            TierId::Two
                if dwelt
                    && !self.backoff.locked(now)
                    && self.unqueued.held(now, CLIMB_3_ROUNDS, CLIMB_3_TIME)
                    && self.signals.trend_share() >= GENTLE_LOSS_CAP =>
            {
                Some((TierId::Three, "loss at the cap without a queue", false))
            }
            TierId::Two if dwelt && self.quiet.held(now, QUIET_ROUNDS, QUIET_TIME) => {
                Some((TierId::One, "quiet", false))
            }
            _ => None,
        };
        if let Some((to, reason, failed)) = decision {
            if failed {
                self.backoff.fail(now);
            }
            self.switch(now, to, reason);
        }
    }

    /// Tier 2's loss baseline is the 32 MiB loss trend at 1 -> 2, but a link that turned lossy a
    /// moment ago still has clean bytes in that window, so the trend at entry is low and still
    /// rising. Until tier 2 has sent a whole trend window of its own, the baseline follows the trend
    /// up (never down); from then on it holds. Measured without this: a 1% phase entered tier 2 at a
    /// trend of about 0.5%, the window then filled to 1%, which read as risen, and tier 2 cut like
    /// Cubic (45–60 Mbit/s at the end of the phase, 1.68x a Cubic flow on the 1% arm).
    fn settle_tier2_baseline(&mut self) {
        let Some(baseline) = self.tier2_baseline else {
            return;
        };
        if self.tier_id == TierId::One || self.tier2_sent >= TREND_BYTES {
            self.tier2_baseline = None;
            return;
        }
        let trend = self.signals.trend_share();
        if trend > baseline {
            self.signals.mark_loss_baseline();
            self.tier2_baseline = Some(trend);
        }
    }

    /// The rate a window sustains over a round trip, bytes per second.
    fn window_rate(window: u64, rtt: Duration) -> u64 {
        if rtt.is_zero() {
            0
        } else {
            (window as f64 / rtt.as_secs_f64()) as u64
        }
    }

    fn switch(&mut self, now: Instant, to: TierId, reason: &str) {
        let from = self.tier_id;
        let window = self.tier.controller().window();
        let min_rtt = self.signals.min_rtt().unwrap_or(Duration::ZERO);
        let last_sent_pn = self.signals.last_sent_pn();
        let replacement = match (&self.tier, to) {
            (Tier::Cubic(_), TierId::Three) => Some(Tier::Bbr(Box::new(VoxBbr::seeded(
                now,
                self.mtu,
                RateSeed {
                    delivery_rate: Self::window_rate(window, self.signals.srtt()),
                    min_rtt,
                    window,
                    last_sent_pn,
                },
            )))),
            (Tier::Bbr(bbr), _) => {
                let rtt = if min_rtt.is_zero() {
                    bbr.min_rtt()
                } else {
                    min_rtt
                };
                let bdp = (bbr.delivery_rate() as f64 * rtt.as_secs_f64()) as u64;
                Some(Tier::Cubic(VoxCubic::seeded(
                    now,
                    self.mtu,
                    last_sent_pn,
                    if bdp == 0 { window } else { bdp },
                )))
            }
            (Tier::Cubic(_), _) => None,
        };
        if let Some(tier) = replacement {
            self.tier = tier;
        }
        if let Tier::Cubic(cubic) = &mut self.tier {
            cubic.set_loss_aware(to != TierId::One);
        }
        match (from, to) {
            (TierId::One, TierId::Two) => {
                self.signals.mark_loss_baseline();
                self.tier2_sent = 0;
                self.tier2_baseline = Some(self.signals.trend_share());
            }
            (TierId::Two, TierId::One) => self.signals.clear_loss_baseline(),
            (_, TierId::Three) => self.tier3_entry_rate = self.delivered_rate(now),
            _ => {}
        }
        tracing::debug!(
            target: "vox::congestion",
            from = from.number(),
            to = to.number(),
            reason,
            window_before = window,
            window_after = self.tier.controller().window(),
            loss_share = self.signals.loss_share(),
            trend_share = self.signals.trend_share(),
            delivered_rate = self.delivered_rate(now),
            tier3_entry_rate = self.tier3_entry_rate,
            min_rtt_us = min_rtt.as_micros() as u64,
            round_min_rtt_us = self.signals.round_min_rtt().map_or(0, |d| d.as_micros() as u64),
            srtt_us = self.signals.srtt().as_micros() as u64,
            losses_without_queue_last_8 = self.signals.losses_without_queue_in_last(8),
            losses_with_queue_last_8 = self.signals.losses_with_queue_in_last(8),
            rounds_in_tier = self.rounds_in_tier,
            "congestion tier switch"
        );
        self.tier_id = to;
        self.entered_at = now;
        self.rounds_in_tier = 0;
        self.unqueued.reset();
        self.queued.reset();
        self.quiet.reset();
        self.loss_gone.reset();
    }
}

impl Controller for Tapered {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.signals.on_sent(now, bytes, last_packet_number);
        self.tier2_sent = self.tier2_sent.saturating_add(bytes);
        self.tier
            .controller_mut()
            .on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.signals.on_ack(now, sent, bytes, app_limited, rtt);
        self.acked_total = self.acked_total.saturating_add(bytes);
        // One point per RATE_POINT: the rate over the window is the bytes since the oldest point,
        // and the total keeps counting between points, so nothing is lost by not storing each.
        if self
            .acked
            .back()
            .is_none_or(|&(t, _)| now.saturating_duration_since(t) >= RATE_POINT)
        {
            self.acked.push_back((now, self.acked_total));
        }
        while self
            .acked
            .front()
            .is_some_and(|&(t, _)| now.saturating_duration_since(t) > RATE_WINDOW)
        {
            self.acked.pop_front();
        }
        self.tier
            .controller_mut()
            .on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        let rounds = self.signals.rounds();
        self.signals
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        self.tier.controller_mut().on_end_acks(
            now,
            in_flight,
            app_limited,
            largest_packet_num_acked,
        );
        if self.signals.rounds() != rounds {
            self.on_round(now);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // PathSignals judges whether this loss is congestion, in one place for every tier.
        let congestion = self
            .signals
            .on_loss(now, lost_bytes, is_persistent_congestion);
        match &mut self.tier {
            Tier::Cubic(cubic) => {
                cubic.on_loss(now, sent, is_persistent_congestion, lost_bytes, congestion)
            }
            Tier::Bbr(bbr) => {
                bbr.on_congestion_event(now, sent, is_persistent_congestion, lost_bytes)
            }
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.tier.controller_mut().on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.tier.controller().window()
    }

    fn metrics(&self) -> ControllerMetrics {
        self.tier.controller().metrics()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.tier.controller().initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
