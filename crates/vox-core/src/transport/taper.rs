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
//!   losses with no queue building, once tier 1's dwell is over. Tier 1's loss share
//!   is marked as tier 2's baseline: loss that then grows with Vox's own sending is congestion.
//! - **Climb 2 → 3** when the loss share over the last 32 MiB sent (`PathSignals::trend_share`)
//!   is at or above [`GENTLE_LOSS_CAP`], past which tier 2 cuts for every loss, and no queue has
//!   been held for [`CLIMB_3_QUEUE_ROUNDS`] rounds in the last [`CLIMB_3_ROUNDS`] rounds and
//!   [`CLIMB_3_TIME`]. Not the share over the last few rounds: at 8 KB datagrams eight rounds
//!   hold a couple of hundred packets, and on a link losing 5% at random that share read 0–14%
//!   from one half-second to the next, so a streak of rounds at the cap never reached 20 and tier 3
//!   was never entered (measured: 1.42x and 1.62x a Cubic flow, against BBR's 7.68x). Nor a
//!   single round's queue: one round in the trace read 39 ms on a 10.6 ms base with nothing else
//!   on the path. **The loss share is the clean-LAN guard:** a clean link loses only when its
//!   queue overflows, well under 1% of what it sends, so it never reaches BBR.
//! - **Tier 3 is on trial for its whole stay.** A shallow buffer under congestion shows the same
//!   entry signal as random loss; they part once Vox sends harder, since random loss stays flat
//!   with the rate and congestion loss climbs. So whenever the loss share rises past
//!   `max(1.5 × entry, entry + TIER3_LOSS_RISE)` (`PathSignals::loss_risen`), tier 3 falls back to
//!   tier 2 and is locked out for a back-off: [`BACKOFF_FIRST`], doubling with each failure up to
//!   [`BACKOFF_MAX`], and back to the first only after a tier-3 stay of [`BACKOFF_RESET`] without
//!   one. An ECN mark or persistent congestion is a failure too, at once.
//! - **Descend 3 → 2 on a queue** held for [`TIER3_QUEUE_ROUNDS`] rounds, dwell or not (rule 3:
//!   BBR must never hold a congested path). Tier 3 has its own queue test. quinn paces from the
//!   window and the smoothed round trip, never from BBR's pacing rate, so BBR here is
//!   window-bound: its window (twice the bandwidth-delay product, plus the acknowledgement
//!   aggregation it measured) can raise the round trip to `window / rate` with no other flow on
//!   the path. Measured on a 200 Mbit/s, 10.7 ms path with 1% loss and no other flow: round
//!   minimums of 18–38 ms against a `window / rate` of up to 39 ms. So a round's minimum round trip
//!   past [`TIER3_QUEUE_FACTOR`] × `max(base, window / rate)` + [`TIER3_QUEUE_MIN`] is another
//!   flow's queue. The other tiers' test (a share of the base) read BBR's own queue as congestion
//!   and took tier 3 out within a second, every time.
//! - **Descend 3 → 2 when the loss is gone:** the loss share under half [`GENTLE_LOSS_CAP`] for
//!   [`QUIET_ROUNDS`] rounds and [`QUIET_TIME`].
//! - **Descend 2 → 1** after a quiet stretch: [`QUIET_ROUNDS`] consecutive rounds and
//!   [`QUIET_TIME`] with no loss, no queue, and delivery at least [`HOLDING_FRACTION`] of the best
//!   rate. Tier 2's loss baseline is cleared.
//! - **Hysteresis and dwell.** Each climb and its descent test different things, and a descent
//!   needs a longer stretch than a climb. Every tier is left no sooner than [`DWELL_ROUNDS`]
//!   rounds and [`DWELL_TIME`], except tier 3 by a queue or a failed trial.
//!
//! An application-limited round is no evidence either way.
//!
//! # Hand-off (rule 5)
//! A switch hands the connection's rate on, so it never pays slow start again:
//! - **into BBR**: [`VoxBbr::seeded`] with the best rate, the windowed minimum round trip and the
//!   current window, in ProbeBw, never Startup: Startup's 2.885 gain on a congested path is what
//!   the trial must not risk;
//! - **out of BBR**: [`VoxCubic::seeded`] in congestion avoidance at BBR's delivery rate times the
//!   windowed minimum round trip.
//!
//! # Troubleshooting
//! Each switch emits `tracing::debug!` under the target `vox::congestion`, with the tiers, the
//! reason and the signal that decided it. Nothing prints by default.

use std::any::Any;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerMetrics};
use quinn_proto::RttEstimator;

use super::congestion::{PathSignals, VoxCubic, GENTLE_LOSS_CAP};
use super::vox_bbr::{RateSeed, VoxBbr};

/// The rounds a climb from tier 1 looks back over…
pub(crate) const CLIMB_1_ROUNDS: usize = 8;
/// …and the losses with no queue building it needs in them.
pub(crate) const CLIMB_1_LOSSES: u32 = 3;
/// Consecutive rounds without a held queue for a climb from tier 2…
pub(crate) const CLIMB_3_ROUNDS: u32 = 20;
/// …spanning at least this long; a queue is held when it shows for this many rounds in a row.
pub(crate) const CLIMB_3_TIME: Duration = Duration::from_secs(2);
/// The rounds in a row a queue must show to break a climb from tier 2.
pub(crate) const CLIMB_3_QUEUE_ROUNDS: u32 = 2;
/// Tier 3 fails when the loss share rises this much above its share at entry (or 1.5 times it).
pub(crate) const TIER3_LOSS_RISE: f64 = 0.03;
/// Tier 3 is locked out this long after a first failure…
pub(crate) const BACKOFF_FIRST: Duration = Duration::from_secs(30);
/// …doubling with each further one, up to this…
pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(480);
/// …and back to the first after a tier-3 stay this long without one.
pub(crate) const BACKOFF_RESET: Duration = Duration::from_secs(300);
/// Consecutive rounds of a queue that take tier 3 to tier 2.
pub(crate) const TIER3_QUEUE_ROUNDS: u32 = 2;
/// In tier 3, a round's minimum round trip past this multiple of the round trip BBR can raise by
/// itself…
pub(crate) const TIER3_QUEUE_FACTOR: f64 = 1.25;
/// …plus this, is a queue another flow is building (see the module docs).
pub(crate) const TIER3_QUEUE_MIN: Duration = Duration::from_millis(4);
/// A quiet round delivers at least this share of the best rate.
pub(crate) const HOLDING_FRACTION: f64 = 0.8;
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
            self.rounds += 1;
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

/// Tier 3's lockout after failures.
#[derive(Debug, Clone, Copy, Default)]
struct Backoff {
    /// The lockout the next failure imposes ([`BACKOFF_FIRST`] when `None`).
    next: Option<Duration>,
    until: Option<Instant>,
}

impl Backoff {
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
    /// The loss share when tier 3 was entered.
    entry_share: f64,
    backoff: Backoff,
    /// Rounds without a held queue, toward a climb from tier 2.
    unqueued: Streak,
    /// Rounds in a row that showed a queue (any tier but 3).
    queued: Streak,
    quiet: Streak,
    loss_gone: Streak,
    queue: Streak,
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
            entry_share: 0.0,
            backoff: Backoff::default(),
            unqueued: Streak::default(),
            queued: Streak::default(),
            quiet: Streak::default(),
            loss_gone: Streak::default(),
            queue: Streak::default(),
        }
    }

    /// The round trip BBR's own window can raise with no other flow on the path.
    fn bbr_own_rtt(bbr: &VoxBbr, base: Duration) -> Duration {
        let rate = bbr.delivery_rate();
        if rate == 0 {
            return base;
        }
        base.max(Duration::from_secs_f64(bbr.window() as f64 / rate as f64))
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
        let share = self.signals.loss_share();
        let queued = self.signals.queue_building();
        let tier3_queued = match (
            &self.tier,
            self.signals.round_min_rtt(),
            self.signals.min_rtt(),
        ) {
            (Tier::Bbr(bbr), Some(round_min), Some(base)) => {
                round_min
                    >= Self::bbr_own_rtt(bbr, base).mul_f64(TIER3_QUEUE_FACTOR) + TIER3_QUEUE_MIN
            }
            _ => false,
        };
        let lossy =
            self.signals.losses_without_queue_in_last(1) > 0 || self.signals.loss_with_queue();
        let holding = self.signals.delivery_rate() as f64
            >= HOLDING_FRACTION * self.signals.best_rate(now) as f64;

        self.queue.update(now, tier3_queued);
        self.queued.update(now, queued);
        self.unqueued
            .update(now, self.queued.rounds < CLIMB_3_QUEUE_ROUNDS);
        self.quiet.update(now, !queued && !lossy && holding);
        self.loss_gone.update(now, share < GENTLE_LOSS_CAP / 2.0);

        let dwelt = self.rounds_in_tier >= DWELL_ROUNDS && in_tier >= DWELL_TIME;
        let decision = match self.tier_id {
            TierId::Three if self.queue.rounds >= TIER3_QUEUE_ROUNDS => {
                Some((TierId::Two, "a queue is building", false))
            }
            TierId::Three if self.signals.loss_risen(self.entry_share, TIER3_LOSS_RISE) => {
                Some((TierId::Two, "the loss rose with the rate", true))
            }
            TierId::Three if dwelt && self.loss_gone.held(now, QUIET_ROUNDS, QUIET_TIME) => {
                Some((TierId::Two, "the loss is gone", false))
            }
            TierId::One
                if dwelt
                    && self.signals.losses_without_queue_in_last(CLIMB_1_ROUNDS)
                        >= CLIMB_1_LOSSES =>
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
                    delivery_rate: self.signals.best_rate(now),
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
            (TierId::One, TierId::Two) => self.signals.mark_loss_baseline(),
            (TierId::Two, TierId::One) => self.signals.clear_loss_baseline(),
            (_, TierId::Three) => self.entry_share = self.signals.trend_share(),
            _ => {}
        }
        tracing::debug!(
            target: "vox::congestion",
            from = from.number(),
            to = to.number(),
            reason,
            window_before = window,
            window_after = self.tier.controller().window(),
            rate = self.signals.delivery_rate(),
            best_rate = self.signals.best_rate(now),
            loss_share = self.signals.loss_share(),
            trend_share = self.signals.trend_share(),
            entry_share = self.entry_share,
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
        self.queue.reset();
    }
}

impl Controller for Tapered {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.signals.on_sent(now, bytes, last_packet_number);
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
        // An ECN mark or persistent congestion takes tier 3 down at once, and the Cubic it hands
        // to takes Cubic's cut for it below.
        if self.tier_id == TierId::Three && (is_persistent_congestion || lost_bytes == 0) {
            self.backoff.fail(now);
            self.switch(now, TierId::Two, "ECN mark or persistent congestion");
        }
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
