//! The tapered congestion controller's tier switch (ADR-024, M24.4).
//!
//! # Tiers
//! | Tier | Controller |
//! |---|---|
//! | 1 | [`VoxCubic`]: every loss is congestion |
//! | 2 | [`VoxCubic`], loss-aware: a loss that [`PathSignals`] does not judge congestion is cut gently (M24.3) |
//! | 3 | [`VoxBbr`]: quinn's BBR, owned by Vox |
//!
//! Every connection starts in tier 1 and moves **one tier at a time, both ways** (ADR-024 rules 1
//! and 2). The decisions here read [`PathSignals`], which measures the path from the controller
//! callbacks whichever tier is running, so a tier is never judged by its own model.
//!
//! # Decisions, evaluated once per round trip
//! - **Climb 1 → 2** when the last [`CLIMB_1_ROUNDS`] rounds held at least [`CLIMB_1_LOSSES`]
//!   losses with no queue building, no sooner than [`TIER_1_DWELL`] in tier 1: Cubic is backing
//!   off for loss that is not congestion.
//! - **Climb 2 → 3, on trial**, when for [`STARVED_ROUNDS`] consecutive rounds and
//!   [`STARVED_TIME`] the loss share stayed at or above [`GENTLE_LOSS_CAP`] (where tier 2 stops
//!   reading loss as random), no queue built, the rate stayed under [`STARVED_FRACTION`] of the
//!   best rate, and at least [`STARVED_LOSSES`] rounds lost something. **The loss is the clean-LAN
//!   guard:** a clean link loses only when its queue overflows, so it never holds a loss share of
//!   5% round after round, and never reaches BBR, the tier both measured BBRs collapse on.
//! - **The trial.** A shallow buffer under congestion shows the same entry signal as random loss.
//!   They part once Vox sends harder: random loss stays flat with the rate, congestion loss climbs.
//!   So for its first [`TRIAL_ROUNDS`] rounds and [`TRIAL_TIME`], tier 3 falls back to tier 2 at
//!   once if the loss share rises past `max(TRIAL_RISE_FACTOR × entry, entry + TRIAL_RISE_ABS)`,
//!   and tier 3 is then locked out for a back-off: [`BACKOFF_FIRST`], doubling with each failed
//!   trial up to [`BACKOFF_MAX`], and forgotten after [`BACKOFF_RESET`] without one.
//! - **Descend 3 → 2 at once** when a queue has been building for [`QUEUE_ROUNDS`] consecutive
//!   rounds (rule 3: BBR must never hold a congested path). In tier 3 the queue test is a round's
//!   minimum round trip [`BBR_QUEUE_SHARE`] of the base above it: BBR's window is twice the
//!   bandwidth-delay product, so BBR alone can stand up to one base round trip of queue, and a
//!   lower test reads BBR's own queue as congestion (measured: half the base took tier 3 out
//!   within a second, every time, on a path with no other flow).
//! - **Descend 3 → 2 when the loss is gone:** the loss share under half [`GENTLE_LOSS_CAP`] for
//!   [`QUIET_ROUNDS`] rounds and [`QUIET_TIME`].
//! - **Descend 2 → 1** after a quiet stretch: [`QUIET_ROUNDS`] consecutive rounds and
//!   [`QUIET_TIME`] with no loss, no queue, and delivery at least [`HOLDING_FRACTION`] of the best
//!   rate.
//! - **Hysteresis.** Each climb and its descent test different things, and a descent needs a
//!   longer stretch than a climb. **Dwell:** tiers 2 and 3 are left no sooner than
//!   [`DWELL_ROUNDS`] rounds and [`DWELL_TIME`], except by rule 3 or a failed trial.
//!
//! A round that was application-limited, or has no rate sample (`delivery_rate()` of 0), is no
//! evidence either way.
//!
//! # Hand-off (rule 5)
//! A switch hands the connection's rate on, so it never pays slow start again:
//! - **into BBR**: [`VoxBbr::seeded`] with the best rate, the windowed minimum round trip and the
//!   current window, in ProbeBw;
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
/// The least time a connection stays in tier 1.
pub(crate) const TIER_1_DWELL: Duration = Duration::from_secs(1);
/// A round delivering under this share of the best rate is starved.
pub(crate) const STARVED_FRACTION: f64 = 0.5;
/// Consecutive starved rounds for a climb from tier 2…
pub(crate) const STARVED_ROUNDS: u32 = 20;
/// …spanning at least this long…
pub(crate) const STARVED_TIME: Duration = Duration::from_secs(2);
/// …in which at least this many rounds lost something.
pub(crate) const STARVED_LOSSES: u32 = 3;
/// Tier 3's trial lasts this many rounds…
pub(crate) const TRIAL_ROUNDS: u32 = 20;
/// …and this long.
pub(crate) const TRIAL_TIME: Duration = Duration::from_secs(2);
/// A trial fails when the loss share rises past this multiple of the share at entry…
pub(crate) const TRIAL_RISE_FACTOR: f64 = 1.5;
/// …or this much above it, whichever is larger.
pub(crate) const TRIAL_RISE_ABS: f64 = 0.03;
/// Tier 3 is locked out this long after a first failed trial…
pub(crate) const BACKOFF_FIRST: Duration = Duration::from_secs(30);
/// …doubling with each further one, up to this…
pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(480);
/// …and back to the first after this long without one.
pub(crate) const BACKOFF_RESET: Duration = Duration::from_secs(300);
/// Consecutive rounds of a queue building that take tier 3 straight to tier 2.
pub(crate) const QUEUE_ROUNDS: u32 = 2;
/// In tier 3, a round's minimum round trip this many base round trips above the base is a queue
/// another flow is building (see the module docs).
pub(crate) const BBR_QUEUE_SHARE: f64 = 1.5;
/// …and never less than this above it.
pub(crate) const BBR_QUEUE_FLOOR: Duration = Duration::from_millis(4);
/// A quiet round delivers at least this share of the best rate.
pub(crate) const HOLDING_FRACTION: f64 = 0.8;
/// Consecutive rounds of a stretch that descends a tier…
pub(crate) const QUIET_ROUNDS: u32 = 40;
/// …spanning at least this long.
pub(crate) const QUIET_TIME: Duration = Duration::from_secs(4);
/// The fewest rounds tiers 2 and 3 run before they may be left…
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
    losses: u32,
}

impl Streak {
    fn extend(&mut self, now: Instant, lossy: bool) {
        self.rounds += 1;
        self.since.get_or_insert(now);
        self.losses += u32::from(lossy);
    }
    fn reset(&mut self) {
        *self = Self::default();
    }
    fn lasted(&self, now: Instant) -> Duration {
        self.since
            .map_or(Duration::ZERO, |t| now.saturating_duration_since(t))
    }
}

/// Tier 3's lockout after failed trials.
#[derive(Debug, Clone, Copy, Default)]
struct Backoff {
    /// The lockout the next failed trial imposes.
    next: Option<Duration>,
    until: Option<Instant>,
    last_failure: Option<Instant>,
}

impl Backoff {
    fn locked(&self, now: Instant) -> bool {
        self.until.is_some_and(|t| now < t)
    }
    fn fail(&mut self, now: Instant) {
        if self
            .last_failure
            .is_some_and(|t| now.saturating_duration_since(t) >= BACKOFF_RESET)
        {
            self.next = None;
        }
        let lockout = self.next.unwrap_or(BACKOFF_FIRST);
        self.until = Some(now + lockout);
        self.next = Some((lockout * 2).min(BACKOFF_MAX));
        self.last_failure = Some(now);
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
    /// The loss share when tier 3 was entered: its trial's baseline.
    entry_share: f64,
    backoff: Backoff,
    starved: Streak,
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
            starved: Streak::default(),
            quiet: Streak::default(),
            loss_gone: Streak::default(),
            queue: Streak::default(),
        }
    }

    /// One round has finished: update the streaks, and switch tier if they say so.
    fn on_round(&mut self, now: Instant) {
        self.rounds_in_tier = self.rounds_in_tier.saturating_add(1);
        if self.signals.app_limited() || self.signals.delivery_rate() == 0 {
            return;
        }
        let rate = self.signals.delivery_rate() as f64;
        let best = self.signals.best_rate(now) as f64;
        let share = self.signals.loss_share();
        let queued = self.signals.queue_building();
        let bbr_queued = match (self.signals.round_min_rtt(), self.signals.min_rtt()) {
            (Some(round_min), Some(base)) => {
                round_min >= base + BBR_QUEUE_FLOOR.max(base.mul_f64(BBR_QUEUE_SHARE))
            }
            _ => false,
        };
        let lossy =
            self.signals.losses_without_queue_in_last(1) > 0 || self.signals.loss_with_queue();

        let streak = |s: &mut Streak, holds: bool, lossy: bool| {
            if holds {
                s.extend(now, lossy);
            } else {
                s.reset();
            }
        };
        streak(&mut self.queue, bbr_queued, false);
        streak(
            &mut self.starved,
            share >= GENTLE_LOSS_CAP && !queued && rate < STARVED_FRACTION * best,
            lossy,
        );
        streak(
            &mut self.quiet,
            !queued && !lossy && rate >= HOLDING_FRACTION * best,
            false,
        );
        streak(&mut self.loss_gone, share < GENTLE_LOSS_CAP / 2.0, false);

        let in_tier = now.saturating_duration_since(self.entered_at);
        let dwelt = self.rounds_in_tier >= DWELL_ROUNDS && in_tier >= DWELL_TIME;
        let in_trial = self.rounds_in_tier < TRIAL_ROUNDS || in_tier < TRIAL_TIME;
        let trial_limit =
            (self.entry_share * TRIAL_RISE_FACTOR).max(self.entry_share + TRIAL_RISE_ABS);
        let stretch = |s: &Streak| s.rounds >= QUIET_ROUNDS && s.lasted(now) >= QUIET_TIME;
        let decision = match self.tier_id {
            TierId::Three if self.queue.rounds >= QUEUE_ROUNDS => {
                Some((TierId::Two, "a queue is building"))
            }
            TierId::Three if in_trial && share > trial_limit => {
                self.backoff.fail(now);
                Some((TierId::Two, "trial failed: the loss rose with the rate"))
            }
            TierId::Three if dwelt && stretch(&self.loss_gone) => {
                Some((TierId::Two, "the loss is gone"))
            }
            TierId::One
                if in_tier >= TIER_1_DWELL
                    && self.signals.losses_without_queue_in_last(CLIMB_1_ROUNDS)
                        >= CLIMB_1_LOSSES =>
            {
                Some((TierId::Two, "loss without a queue"))
            }
            TierId::Two
                if dwelt
                    && !self.backoff.locked(now)
                    && self.starved.rounds >= STARVED_ROUNDS
                    && self.starved.lasted(now) >= STARVED_TIME
                    && self.starved.losses >= STARVED_LOSSES =>
            {
                Some((TierId::Three, "starved by loss without a queue"))
            }
            TierId::Two if dwelt && stretch(&self.quiet) => Some((TierId::One, "quiet")),
            _ => None,
        };
        if let Some((to, reason)) = decision {
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
            cubic.set_loss_aware(to == TierId::Two);
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
            entry_share = self.entry_share,
            min_rtt_us = min_rtt.as_micros() as u64,
            round_min_rtt_us = self.signals.round_min_rtt().map_or(0, |d| d.as_micros() as u64),
            srtt_us = self.signals.srtt().as_micros() as u64,
            starved_rounds = self.starved.rounds,
            quiet_rounds = self.quiet.rounds,
            queue_rounds = self.queue.rounds,
            rounds_in_tier = self.rounds_in_tier,
            "congestion tier switch"
        );
        if to == TierId::Three {
            self.entry_share = self.signals.loss_share();
        }
        self.tier_id = to;
        self.entered_at = now;
        self.rounds_in_tier = 0;
        self.starved.reset();
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
