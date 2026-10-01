# ADR-024: Tapered Congestion Control

**Status**: **Accepted by the decider — 2026-09-25** (the direction and the shape below). **Not built.**
Planned for v0.2.10 (docs/release/v0.2.10.md). M24.1's design is "Signals and thresholds" below;
M24.2–M24.5 are to be built.
**Date**: 2026-09-25
**Updated**: 2026-10-01 — M24.1: the decider's rulings of 2026-10-01, the signals and thresholds as
measured on today's tier 1, and the context restated from today's measurement. (Created 2026-09-25
from the decider's decision on PRD-001 R41's lossy-link arm.)
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: transport, quic, congestion-control, throughput, wireless

## Context

PRD-001 R41 says a Vox tunnel **must not throttle the network it runs over**. The decider's standing
direction for throughput is *"as fast as possible, while still retaining our other goals/security"*.
R41 is measured by `perf_r41_tunnel_throughput_proof` over emulated links: raw TCP and a Vox tunnel
cross the same shaper.

The congestion controller is Cubic: since 2026-09-26, `VoxCubic` in
`crates/vox-core/src/transport/congestion.rs`, quinn-proto 0.11.18's Cubic ported unchanged except that
HyStart++ (RFC 9406, as §4.2 specifies) ends slow start, wrapped in `IdleRestart`, which starts a
fresh controller after the connection idles. Cubic treats every lost packet as a sign of
congestion and cuts its sending rate. On a link that loses packets for reasons other than
congestion, such as Wi-Fi interference, that is the wrong answer: the tunnel slows down for a network
that has spare capacity.

**Measured, 2026-09-25, all in one R41 window** (kept as the record of why BBR was not made the
default; superseded for the lossy link by the 2026-10-01 measurement below) (same machine, same emulator, share of raw TCP over
the same link). Arms are recorded on the `agentcomms/exp-*` branches.

| Controller | 1 Gbit/s LAN, 2 ms | 1 Gbit/s WAN, 50 ms | 200 Mbit/s Wi-Fi-like, 1% loss |
|---|---|---|---|
| quinn 0.11 Cubic (shipped) | 98.9% | 14.8%¹ | **4.5%** |
| quinn 0.11 BBRv1 (`BbrConfig`) | **28.4%** | 1.1% | 21.4% |
| noq 1.3 Cubic (the stack alone) | 98.5% | 14.7% | 5.9% |
| noq 1.3 BBRv3 (`Bbr3Config`) | **29.6%** | 16.5% | 18.5% |

¹ The WAN arm is limited by flow-control windows, not by the controller. ADR-011 "Throughput (R41)"
raises the windows; this ADR does not concern them.

- **Each BBR trades one link for another.** It does roughly 4× better on random loss, but a clean
  LAN drops by about 70%. Switching the default to BBR, or moving to noq for BBRv3, would make the
  common case worse to fix the rare one.
- **The LAN collapse is real, not an emulator artefact.** The emulator was rebuilt to release packets
  precisely (sleep until 200 µs before each release, then spin). noq BBRv3 still ran at 37–44% of raw
  in 5 of 6 runs; one run reached 98.6%. With the original emulator it ran at 29.7–42.4%. Cubic held
  97.5–99.0% under both, and the emulator's measured fidelity was 98% throughout.
- **noq's stack alone changes nothing** (noq Cubic ≈ quinn Cubic). There is no throughput reason to
  change the QUIC stack.

**Measured again, 2026-10-01** on **tree B**: integrate/v0.2.10 76e5c2c4, where tier 1 is `VoxCubic`
exactly as it ships, plus a spike harness that is never committed (local commit 9a63e0ab: a
controller chosen by environment variable, a per-loss trace, and the emulator arms). Release build,
one run per row, under the shared timing lock at the load of a machine doing ordinary work; how each
figure is derived is under "Method" below. Vox sends 8192-byte datagrams. The comparison is no longer
raw TCP behind a proxy, which never sees the link's loss, but TCP's algorithm over the same link
("The comparison flow" below).

| Link | Vox, today's tier 1 | Cubic flow, same link | Vox / Cubic |
|---|---|---|---|
| 200 Mbit/s, 10 ms, 1% random loss | 63.2 Mbit/s | 61.2 Mbit/s | **1.03×** |
| 200 Mbit/s, 10 ms, 5% random loss | 23.9 Mbit/s | 23.7 Mbit/s | **1.01×** |
| 200 Mbit/s, 10 ms, shared, 1-BDP queue | 90.7 Mbit/s | 105.4 Mbit/s | 0.86× |
| 200 Mbit/s, 10 ms, shared, ¼-BDP queue | 33.4 Mbit/s | 33.8 Mbit/s | 0.99× |
| 400 Mbit/s, 2 ms, shared, 1-BDP queue | 166.0 Mbit/s | 176.8 Mbit/s | 0.94× |

The 4.5% figure of 2026-09-25 is stale: with 8192-byte datagrams the same 1% loss costs far fewer
reductions per byte. Today's Vox matches a Cubic flow on a lossy link; the decider's bar is twice it.

**Why quinn's BBR collapsed on a clean LAN** (fix-adr024-bbr, 2026-10-01; one run each, so smoke-grade
until M24.4 proves it). quinn's BBR takes its minimum round trip from `RttEstimator::min`, which is the
connection's lifetime minimum and read 0 µs in the spike on a connection that had first run unshaped;
and its bandwidth filter accepts only samples above its current maximum, so the estimate never
decays. A port with BBR's own 10 s windowed minimum round trip and the BBR draft's delivery-rate
samples, every sample fed to the max filter, held a clean 1 Gbit/s, 2 ms link at 962, 962 and
940 Mbit/s, where tier 1 on the same link ran 983, 988 and 983: about 96–98% of Cubic, not 28%.

**Prior art.**
- *Loss differentiation.* TCP Westwood and TCP Veno tell random (wireless) loss from congestion loss
  by bandwidth estimation (Westwood) or by whether the connection is in a congestive state (Veno), and
  do not back off on the former. Known weakness: heavy cross traffic can make congestion loss look
  random.
- *Switching algorithms mid-flow.* Antelope (ICNP 2021; IEEE/ACM ToN 2023) classifies each flow's
  conditions and changes its algorithm while the connection runs. It showed that switching between
  Cubic, BBR and Westwood can be done smoothly. Libra (2025) combines a classic controller with a
  learned one.

## Decision

**A tapered controller.** One Vox controller, a custom quinn `ControllerFactory`, is to hold three
tiers and move between them one tier at a time. **The taper goes both ways.** No change of QUIC
stack; quinn itself is not patched.

| Tier | Behaviour | Entered when |
|---|---|---|
| **1 — Cubic** | `VoxCubic`, as today: quinn-proto 0.11.18's Cubic with HyStart++ per RFC 9406 §4.2, restarted after idle. | Every connection starts here. A clean link never leaves. |
| **2 — Loss-aware Cubic** | `VoxCubic`, except that a loss the path signals do not call congestion is to cost **no** reduction (M24.1 measured that a smaller one is not enough). A loss with a queue, past the loss cap, past the loss trend, under persistent congestion or from an ECN mark is to cost Cubic's normal reduction. | From tier 1, when losses keep arriving without a queue. |
| **3 — BBR** | `VoxBbr`, to be a Vox-owned port of quinn-proto 0.11.18's BBR (the decider, 2026-10-01), so that a switch into it can be seeded with the current rate, which quinn's `BbrConfig` cannot be. | From tier 2, **on trial**, when the loss stays above tier 2's cap without a queue: random loss heavier than tier 2 can carry. |

**Rules.**
1. **Climbing is one tier at a time, and only on sustained evidence** measured over many round trips,
   never on a single event.
2. **Descending is also one tier at a time** (tier 3 → 2 → 1) after a quiet stretch. Each step is
   re-checked before the next.
3. **Congestion leaves tier 3 without waiting for its dwell:** a queue held for two rounds, an ECN mark,
   persistent congestion, or loss that grows with Vox's sending (a failed trial) takes tier 3 to tier 2.
   BBR fails on a congested path, so it must never be the tier holding one.
4. **No flapping.** Each tier has a minimum dwell time, and the thresholds to climb and to descend
   differ (hysteresis).
5. **A switch does not restart the connection's ramp.** The current rate and window are handed to
   the next tier, so moving between tiers does not cost a slow start.
6. **Security and consent are untouched.** This changes only the congestion controller, which runs
   inside quinn and sees no plaintext, keys or identities.

## Signals and thresholds (M24.1, measured 2026-10-01)

All three tiers are to read one helper, `PathSignals` in `crates/vox-core/src/transport/congestion.rs`, fed
from quinn's `Controller` callbacks; its names below are the constants it is to define. Rounds are to
be counted in packet numbers (a round ends when a packet sent after it began is acknowledged), and
each acknowledgement's round-trip sample is to be its own `now - sent`.

### The comparison flow

**The comparison is TCP's algorithm (Cubic), run over the same simulated link; not kernel TCP, which
needs root to shape** (the decider, 2026-10-01, through vox: this stand-in counts as TCP for v0.2.10;
a race against real kernel TCP on Linux CI is optional, later). A kernel TCP connection cannot see an emulated loss
or share an emulated queue without root (dummynet or pf on macOS, netem on Linux), and Vox's agents
never run as root. So R41's comparison is to be a **quinn-Cubic flow**: a QUIC flow under quinn's
stock `CubicConfig` (RFC 8312), with QUIC's acknowledgement ranges for loss recovery, the tunnel's
8192-byte datagram ceiling and windows, crossing the same emulated link, the same loss draw and, on
the congested arms, the same queue. Cubic is what macOS TCP runs by default (`sysctl
net.inet.tcp.use_newreno` reads 0 on the Mac these were measured on) and what Linux runs by default.
**The fairness claims are against RFC 8312 Cubic, not against any kernel's TCP.** Known differences:
the comparison has no HyStart, no PRR and no RACK, and quinn paces from the window. On a lossy link
a kernel TCP with RACK and PRR is likely to do somewhat better than this flow, so "2× the Cubic flow"
is likely softer than "2× kernel TCP"; that has not been measured.

### Method

Two spike trees were measured, both never committed to the product:

- **Tree B** (the figures quoted first everywhere below): integrate/v0.2.10 76e5c2c4, with tier 1 as
  it ships, plus the spike harness (local commit 9a63e0ab).
- **Tree A** (earlier, kept only where a row shows a mechanism tree B did not re-run, and labelled
  "tree A"): integrate/v0.2.10 5a2c1c23 plus #294 c1 (ec52c8bd) plus ac-fix98's HyStart++ change
  f5fc7c7f, which the decider withdrew (RFC 9406 §4.2 stands). That change only decides when slow
  start ends, and every tree-A figure is a mean over seconds judged long after loss had ended slow
  start; the rows are still labelled, not mixed with tree B's.

Every derived figure was computed by one script (`docs/adr/ADR-024-reviews/m241-analyze.py`), over
the run logs and per-loss traces committed in `docs/adr/ADR-024-reviews/runs/`; it prints its method
with its output: the RESULT line of each run (means over the last two thirds of the run's timeline);
loss share = lost bytes over lost plus acknowledged bytes, and queue rise = the last finished round's
minimum round trip minus the windowed base, both over trace lines at least 17 s into the sending
process (past the unshaped warm-up and the 10 s base window), with nearest-rank percentiles; the
emulator's lateness is the largest per half-second window of the run.

**When an arm measures the emulator, not Vox.** Tier 2's queue test reads a 4 ms rise in a round's
minimum round trip, and an emulator that releases late can fake or hide one. But a round's minimum is
over every packet in the round (about 25 at 200 Mbit/s), so one late release does not move it; only
sustained lateness does. R41's arms are therefore to print the emulator's lateness per second, and an
arm is CANNOT MEASURE when the emulator ran at least 4 ms late in more than 10% of its judged
seconds, or in its median second, as well as when any second ran more than 25 ms late (the bound
R41's raw-TCP links use). A bound on the worst second alone would make nearly every arm CANNOT
MEASURE on a machine doing ordinary work: the worst second of every 200 Mbit/s spike run was 8–19 ms.
The 10% is to be calibrated from the per-arm counts R41 prints. The tier-2 rows give the loss
trend the loss share the tier-1 run on the same link measured, as tier 2 is to take it on entry.

### Base round trip: a 10 s windowed minimum (`BASE_RTT_WINDOW`)

quinn's `RttEstimator::min` is the connection's lifetime minimum; in the spike it read 0 µs on a
connection that had first run unshaped, so every loss looked like a queue. A tunnel's connection
outlives the network it started on, so its base must expire. **Warm-up cost, measured:** for about
10 s after a path's round trip grows, the old base makes every loss read as congestion and Vox runs
at tier 1's rate; in tree A's 1%-loss run the tunnel ran 95–198 Mbit/s per half second after 10.5 s,
against the Cubic flow's 61.4. When the round trip shrinks, the base follows at once.

### A queue is building (`QUEUE_DELAY_MIN`, `QUEUE_DELAY_SHARE`)

When the last finished round's **minimum** round trip exceeds the base by at least
**max(4 ms, 40% of the base)**. A round's minimum, not the smoothed round trip: one delayed
acknowledgement must not read as a queue. Measured rise at each loss (tree B unless labelled):

| Link | Controller | rise at a loss: p10 / p50 / p90 / p99 | read as a queue |
|---|---|---|---|
| 200 Mbit/s, 10 ms, 1% random loss | tier 1 | 0.39 / 1.14 / 3.20 / 11.76 ms | 13.7% |
| same | tier 2 | 0.47 / 1.96 / 4.12 / 5.57 ms | 9.9% |
| 200 Mbit/s, 10 ms, 1-BDP queue, shared | tier 1 | 3.96 / 6.44 / 8.34 / 11.76 ms | 92.9% |
| same | tier 2 | 2.25 / 6.22 / 8.48 / 10.35 ms | 73.7% |
| 400 Mbit/s, 2 ms, 1-BDP queue, shared | tier 2 | 0.66 / 1.46 / 1.86 / 6.68 ms | 3.1% |

The test sits above most of the noise of a link with no queue (the 10–14% it reads as a queue there
is a brake on tier 2 once it fills the link) and below what a shared queue shows at 10 ms. **It is
blind where a full queue is shorter than its floor:** at 2 ms a whole bandwidth-delay product of queue
is 2 ms of delay. There the loss signals below are the only guard.

### Tier 2's response: no cut on a loss that is not congestion

| 200 Mbit/s, 10 ms, 1% loss | Vox | Cubic flow | Vox / Cubic |
|---|---|---|---|
| tier 1 (tree B) | 63.2 | 61.2 | 1.03× |
| tier 2 as designed: no cut, 5% cap, loss trend (tree B) | 191.1 | 59.9 | **3.19×** |
| tier 2, cut to 0.85 on a no-queue loss (tree A) | 63.3 | 62.7 | 1.01× |

At 8192-byte datagrams the window there is 100–130 KB, 12–16 packets (tree A's traces); Cubic's
congestion avoidance regrows it by about half a packet per round trip (RFC 8312's `W_est` slope,
3(1−β)/(1+β) with β = 0.7), and a loss arrives about every eight rounds. Any per-loss cut holds the
rate down, which is why tier 2 is to make none.

### Two loss guards for what the queue test cannot see

**The loss cap: 5% of the bytes sent over the last 8 rounds** (`GENTLE_LOSS_CAP`, `LOSS_ROUNDS`). Past
it, every loss is congestion. It is the guard for a **shallow buffer**, where congestion shows as loss
with almost no delay:

| 200 Mbit/s, 10 ms, ¼-BDP queue (62.5 KB, about 2.5 ms), shared | Vox | Cubic flow | Vox / Cubic | Vox's loss share |
|---|---|---|---|---|
| tier 1 (tree B) | 33.4 | 33.8 | 0.99× | 3.90% |
| tier 2 as designed (tree B) | 47.9 | 38.6 | **1.24×** | 4.59% |
| tier 2 with no cap and no trend (tree A) | 80.9 | 15.4 | **5.26×** | 35.61% |
| tier 2 with the cap, no trend, 80 s (tree A) | 49.8 | 38.8 | 1.29× | 4.57% |

With the guards the Cubic flow keeps what it gets against another Cubic (38.6 against 33.8). In tree
A's 80 s run every 10 s block stayed between 1.12× and 1.38×.

**The loss trend: loss that grows with Vox's sending is congestion** (`LOSS_RISE_FACTOR` 1.5,
`TIER2_LOSS_RISE` 0.5 points, `TREND_BYTES` 32 MiB). On entering tier 2 the loss share of tier 1's
sending is recorded; once the share over the last 32 MiB sent passes max(1.5 × that, that + 0.5
points), every loss is congestion. Random loss does not move with Vox's rate (0.96–1.03% of what Vox
sent at 1% loss, in tier 1 and tier 2); loss Vox causes does. It is the guard for a congested link
whose queue is too short to see and whose loss stays under the cap:

| Shared link, 1-BDP queue, 2 ms | Vox | Cubic flow | Vox / Cubic | Vox's loss share |
|---|---|---|---|---|
| 400 Mbit/s, tier 1 (tree B) | 166.0 | 176.8 | 0.94× | 1.75% |
| 400 Mbit/s, tier 2 as designed (tree B) | 164.5 | 173.5 | **0.95×** | 2.66% |
| 1 Gbit/s, tier 2 with no trend (tree A, emulator up to 53 ms late) | 641.4 | 251.0 | **2.56×** | 2.16% |
| 1 Gbit/s, tier 2 with the trend over 32 MiB (tree A, up to 64 ms late) | 548.3 | 335.4 | 1.63× | 0.85% |

At 400 Mbit/s tier 2's loss share sits at the trend's trigger (2.66% against max(1.5 × 1.75%,
1.75% + 0.5) = 2.63%): this is the fairness arm to watch. The trend is judged over 32 MiB, about four
thousand datagrams, because over 8 rounds (a couple of hundred packets) 1% random loss read above
1.5% by chance often enough to hold the 1%-loss arm to 1.62× (tree A).

### Tier 3: where it earns its place, and its trigger

At 1% loss tier 2 alone clears the decider's 2× (3.19×). Above the cap it cannot: every loss is then
congestion and tier 2 is Cubic.

| 200 Mbit/s, 10 ms | Controller | Vox | Cubic flow | Vox / Cubic | Vox's loss share |
|---|---|---|---|---|---|
| 5% random loss | tier 1 (tree B) | 23.9 | 23.7 | 1.01× | 5.43% |
| 5% random loss | tier 2 as designed (tree B) | 27.8 | 22.8 | 1.22× | 5.37% |
| 5% random loss | quinn's BBR (tree B) | 179.5 | 23.3 | **7.70×** | 5.01% |
| ¼-BDP queue, shared | tier 2 as designed (tree B) | 47.9 | 38.6 | 1.24× | 4.59% |
| ¼-BDP queue, shared | quinn's BBR (tree B; emulator up to 138 ms late, so smoke-grade) | 162.3 | 23.3 | **6.97×, unfair** | 13.00% |
| 1% random loss | `VoxBbr` held in tier 3 (fix-adr024-bbr, smoke; `runs/voxbbr/`) | 195.8 | 62.5 | 3.13× | — |

**The signal that shows tier 3 is needed: loss at or above the cap that does not grow with the rate.**
In tier 2 a 5%-loss Wi-Fi link and a shallow congested queue look alike (loss near the cap, no queue).
Sending harder separates them: random loss stays flat (5.37% under tier 2, 5.01% under BBR at six
times the rate); congestion loss climbs (4.59% to 13.00%). So tier 3 is to be entered on trial, judged
by the same trend test with a wider margin:

- **2 → 3 (a trial):** after tier 2's dwell, the loss share over the last 32 MiB at or above the cap,
  through at least 20 rounds and 2 s in which no queue holds for two rounds in a row. That loss share
  is recorded as the trial's baseline. Not the 8-round share and not "no queue in any round"
  (fix-adr024-bbr's trace at 5% random loss, `runs/voxbbr/trace5.txt` with `r41-5pct.log`): the
  8-round share swung between 0.000 and 0.138, so a streak of rounds at the cap never passed 7 of the
  20 it needed, and single rounds 39.4 ms and 23.7 ms long on a 10.6 ms base reset it; tier 2 never
  climbed and the 5%-loss arm read 1.42×. Tier 3 starts in BBR's steady state (ProbeBW) at the current
  delivery rate, round trip and window, never in Startup, whose 2.885× gain would breach the trial's
  bound.
- **Loss that grows leaves tier 3, at any time in it, not only during the trial:** the share over the
  last 32 MiB passes max(1.5 × the baseline, the baseline + 3 points). That is a failed trial.
- **Back-off after a failed trial:** tier 3 is barred for 30 s, doubled after each failed trial up to
  8 min, and reset to 30 s only after a stay in tier 3 of 5 min with no failure.
- **A queue leaves tier 3 (rule 3): UNMEASURED; its test is an obligation of M24.4.** Tier 3 needs a
  queue test of its own, because BBR stands a queue of its own and the tier-2 test threw it out within
  a second with no other flow (fix-adr024-bbr). The candidate test, the last round's minimum round
  trip at or above `1.25 × max(base, window ÷ delivery rate) + 4 ms` held for two rounds, **does not
  yet work**: in the solo run committed as `runs/voxbbr/lossy-bbr.log` it read a queue in 22 of 68
  samples, up to 4 in a row, with Vox alone; and for a window-limited flow `window ÷ delivery rate` is
  about the current round trip, so the test cancels itself (ac-verm241). M24.4 is to fix the test
  (for instance with BBR's max-filtered bottleneck bandwidth as the rate) and prove both halves on the
  shipped binary: it stays quiet with Vox alone, and it fires on the shared ¼-BDP arm. Until it does,
  ADR-024 makes no claim about rule 3 in tier 3.
- **How tier 3 paces.** quinn-proto 0.11 paces every connection from the window and the smoothed
  round trip; it never reads a controller's pacing rate (`pacing_rate` is reported in metrics only).
  So `VoxBbr`'s gains, including its probing cycle, are to act through its window alone, and its
  seeded rate is to drive sending as `window = rate × round trip`.
- **ECN marks and persistent congestion leave tier 3 at once,** with Cubic's reduction.
- **3 → 2 when the loss goes:** the loss share under half the cap (2.5%) for 40 rounds and 4 s, handed
  down to a `VoxCubic` seeded in congestion avoidance at the delivery rate × the base round trip.

**The trial's cost, plainly.** A trial on a path that turns out to be congested is to take more than
its share from the competing flows for as long as it lasts: on the shallow queue, BBR took 6.97× the
Cubic flow. The rules bound that: each failed trial is to last until the 32 MiB trend window shows
the rise (32 MiB is about 1.5 s at the 180 Mbit/s BBR reached; up to about 3 s while the window still
holds tier 2's rounds), followed by at least 30 s of fair sharing, doubling with every further failure
to 8 min. So a competing flow is to lose its share for at most about 3 s in every 30 s, then in every
minute, then in every 8 minutes. That is the price of reaching 7× on a Wi-Fi link that loses 5% of its
packets. ADR-024 makes no claim about any window shorter than a congested arm's whole run: the arms
are to print the 2 s windows only as a line marked DIAGNOSTIC, never as a verdict.

### An idle restart: the tier resets, the tier-3 back-off survives

`IdleRestart` starts a fresh controller after the connection sends nothing for `IDLE_RESTART` (1 s)
and several round trips, because the path may have changed. The tier and the 10 s base round trip
are to reset with it: the next transfer starts in tier 1 and climbs again (at least the 2 s dwell,
then three losses without a queue). The tier-3 back-off is to survive it: a failed trial is fairness
memory, and pausing must not buy a new trial. R41's "paused" arm (the 1%-loss link, a 3 s pause) is
to show the speed a person sees after the pause.

### Tier 1 ↔ 2 and dwell

- **1 → 2:** at least 3 losses without a queue within 8 rounds, once tier 1's dwell (below) is over.
- **2 → 1:** no loss without a queue for 40 rounds and 4 s.
- **Dwell:** at least 2 s and 20 rounds in a tier before any switch, except rule 3.

### The changing link

Tier 2 with the cap and no trend (tree A; 200 Mbit/s, 10 ms; 20 s clean, 20 s at 1% loss, 20 s clean,
one transfer): 197.6, 173.8 and 197.5 Mbit/s per phase. In the second clean phase the half-second
windows ran 169.1–226.8 Mbit/s (the lowest, 169.1, 18 s after the loss ended); the first three after
the loss ended carried 191.5, 184.6 and 198.8 Mbit/s.

### Not proven: no claim is made for these

ADR-024 makes **no claim** for the cases below: none is measured, and none is to be built for
v0.2.10 (the decider, through vox, 2026-10-01). How the design behaves on them is **unknown**. The
risks, stated plainly:

- **Jittery links (cellular):** delay that varies from round to round may read as a queue, which would
  hold tier 2 at Cubic's behaviour; or may not, in which case its losses are treated as random.
- **Bursty loss:** a burst can push the loss share over the cap. Loss that averages at or above the
  cap with no queue meets tier 3's trial condition, so such a link can enter a tier-3 trial, with the
  trial's cost to any competing flow.
- **AQM (fq_codel, CoDel, CAKE):** early drops at a short queue may read as random loss; whether the
  loss trend catches them, and how flow queueing changes the outcome, is unmeasured.
- **Two or more competing flows, and a shared 50 ms WAN link:** unmeasured.
- **Every threshold** rests on the runs above (one or two per row) at one link rate and round trip per
  case.

## Consequences

### Positive
- Clean links keep Cubic's measured ~98% of raw. Lossy links are to reach 3.2× a Cubic flow at 1% loss
  and about 7× at 5%, without paying BBR's cost where it hurts.
- No dependency change. It stays on quinn 0.11; tier 1 and tier 3 are Vox's ports of quinn's own
  controllers, and quinn is not patched.

### Negative
- Loss differentiation can misread congestion as random loss. If it does, Vox sends harder than is
  fair. The guards are the queue test, the loss cap, the loss trend, the trial entry to tier 3 and
  rule 3; R41's congested arms, at a deep, a shallow and a LAN-length queue, are to prove them.
- A failed tier-3 trial costs competing flows a couple of seconds of their share (above).
- For 10 s after a path's round trip grows, the old base makes every loss read as congestion.
- It is a new controller that Vox must maintain, with its own thresholds.

### Neutral
- If quinn later ships a BBR that holds a clean LAN, tier 3 can adopt it without changing the shape.

## Milestones

- **M24.1 — Design.** State the exact signals and thresholds: the delay-rise test, the test for tier
  3, dwell times and hysteresis. Reviewed by gpt-6-astra, glm-5.3, kimi-k3 and codex, against
  quinn-proto 0.11.18's `Controller` trait and the prior art above. The numbers are in "Signals and
  thresholds".
- **M24.2 — Gate arms first.** R41's arms, driven through the shipped binary and judged by the speed
  a person sees, never by which tier is running (the decider, 2026-10-01), each red naming PRODUCT or
  APPARATUS (emulator late, comparison flow not running):
  - **lossy**, 200 Mbit/s, 10 ms, at 1% and at 5% random loss: Vox carries at least **2×** the
    quinn-Cubic comparison flow on the same loss;
  - **congested**, the link shared with the comparison flow through one queue, at 200 Mbit/s, 10 ms
    with a 1-BDP and a ¼-BDP queue, and at 400 Mbit/s, 2 ms with a 1-BDP queue (a full queue there is
    2 ms, under the queue test's floor), each judged over 60 s
    so tier-3 trials run inside it (the 2 s windows printed as DIAGNOSTIC only): Vox's rate is between **0.5×
    and 2×** the comparison flow's;
  - **changing**, clean → 1% loss → clean and clean → 5% loss → clean under one transfer: every second
    of each clean phase at the clean bar (90% of raw TCP on that clean link), back at it within 5 s of
    the loss ending, and the lossy phase at that loss's lossy-arm bar;
  - **clean LAN-like**, 400 Mbit/s, 2 ms: every one of 30 seconds at the clean bar (90% of raw), the
    proof that a clean link is not held in a tier that slows it. 400 Mbit/s because the userspace
    emulator calibrates that rate on a machine doing ordinary work; R41's 1 Gbit/s LAN link often
    cannot (its weakest calibration window read 78.8%, 75.6% and 82.5% in three runs at load 38–66,
    where each must reach 95%: `runs/r41/`), and stays as it is.

  The lossy arms are to be red on today's tier 1.
- **M24.3 — Tier 2** (loss-aware Cubic) with the queue test, the cap and the trend, proved on all arms.
- **M24.4 — Tier 3** (`VoxBbr`) with the trial, both-way transitions, hysteresis and rate hand-off,
  proved on all arms.
- **M24.5 — Ship.**
  - Acceptance (the decider, 2026-10-01: a fair race): LAN and WAN unchanged against raw (at least
    90%); on each lossy arm Vox carries at least 2× the comparison flow; on each congested arm Vox's
    rate is between 0.5× and 2× the comparison flow's; the changing arms hold as M24.2 states. The post
    says, for each arm, what it shows with tier 3 on and off.
  - Every proof drives the shipped binary and is mutation-checked. R41 is to be an optional proof
    (cargo feature `optional-proofs`, #301): it blocks nothing, and the verifier runs it.

## Links
**Depends on**: ADR-011 (transport substrate), PRD-001 R41.
- Rejected alternatives, as measured: BBRv1 as the default; a move to noq for BBRv3; the noq stack on
  its own. Evidence branches: `agentcomms/exp-bbr`, `agentcomms/exp-noq`, `agentcomms/exp-noq-cubic`.
- Prior art:
  - Antelope, <http://www.eecs.qmul.ac.uk/~tysong/files/ICNP21.pdf>;
  - <https://dl.acm.org/doi/10.1109/TNET.2022.3220225>;
  - TCP Westwood, <https://dl.acm.org/doi/10.1023/A:1016590112381>;
  - TCP Veno, <https://ieeexplore.ieee.org/document/1409272>;
  - Libra, <https://www.computer.org/csdl/journal/nw/2025/02/10765799/224XFcikaFG>.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
