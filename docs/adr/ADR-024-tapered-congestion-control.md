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

The congestion controller is Cubic: since 2026-09-25, `VoxCubic` in
`vox-core/src/transport/congestion.rs`, quinn-proto 0.11.18's Cubic ported unchanged except that
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

**Measured again, 2026-10-01** (the M24.1 spike: release builds of the shipped binary, one run per
row unless a row says otherwise, under the shared timing lock at a load of 55–86; how each figure is
derived is under "Method" below). Tier 1 is now `VoxCubic`, and Vox sends 8192-byte datagrams. The
comparison is no longer raw TCP behind a proxy, which never sees the link's loss, but a Cubic flow
over the same lossy link ("The comparison flow" below).

| Link (200 Mbit/s, 10 ms RTT) | Vox, today's tier 1 | Cubic flow, same link | Vox / Cubic |
|---|---|---|---|
| 1% random loss | 57.3 Mbit/s | 61.7 Mbit/s | **0.93×** |
| 1% random loss, R41 arm on the candidate branch | 61.0 Mbit/s | 60.7 Mbit/s | 1.01× |
| 5% random loss, R41 arm on the candidate branch | 24.2 Mbit/s | 23.7 Mbit/s | 1.02× |
| shared with the Cubic flow, 1-BDP queue | 98.8 Mbit/s | 97.4 Mbit/s | 1.01× |
| shared with the Cubic flow, ¼-BDP queue | 38.3 Mbit/s | 38.1 Mbit/s | 1.00× |

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

All three tiers are to read one helper, `PathSignals` in `vox-core/src/transport/congestion.rs`, fed
from quinn's `Controller` callbacks; its names below are the constants it is to define. Rounds are to
be counted in packet numbers (a round ends when a packet sent after it began is acknowledged), and
each acknowledgement's round-trip sample is to be its own `now - sent`.

### The comparison flow

The decider asked for a fair race against TCP. A kernel TCP connection cannot see an emulated loss
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

Every derived figure here was computed by one script over the spike's run logs and per-loss traces,
which printed its method with its output: the RESULT line of each run (means over the last two
thirds of the run's timeline); loss share = lost bytes over lost plus acknowledged bytes, and queue
rise = the last finished round's minimum round trip minus the windowed base, both over trace lines
at least 17 s into the sending process (past the unshaped warm-up and the 10 s base window), with
nearest-rank percentiles. The emulator ran at most 22 ms late in any half-second window of the
200 Mbit/s runs, and 21–64 ms late in the 1 Gbit/s runs, whose figures are therefore smoke-grade.

### Base round trip: a 10 s windowed minimum (`BASE_RTT_WINDOW`)

quinn's `RttEstimator::min` is the connection's lifetime minimum; in the spike it read 0 µs on a
connection that had first run unshaped, so every loss looked like a queue. A tunnel's connection
outlives the network it started on, so its base must expire. **Warm-up cost, measured:** for about
10 s after a path's round trip grows, the old base makes every loss read as congestion and Vox runs
at tier 1's rate; in the 1%-loss run the tunnel ran 95–198 Mbit/s per half second after 10.5 s,
against Cubic's 62. When the round trip shrinks, the base follows at once.

### A queue is building (`QUEUE_DELAY_MIN`, `QUEUE_DELAY_SHARE`)

When the last finished round's **minimum** round trip exceeds the base by at least
**max(4 ms, 40% of the base)**. A round's minimum, not the smoothed round trip: one delayed
acknowledgement must not read as a queue. Measured rise at each loss:

| Link | Controller | rise at a loss: p10 / p50 / p90 / p99 | read as a queue |
|---|---|---|---|
| 200 Mbit/s, 10 ms, 1% random loss | tier 2, run 1 | 0.60 / 2.19 / 4.39 / 10.38 ms | 12.0% |
| same, repeated | tier 2, run 2 | 0.42 / 1.78 / 4.40 / 6.68 ms | 11.2% |
| 200 Mbit/s, 10 ms, 1-BDP queue, shared | tier 1 | 3.64 / 6.64 / 8.63 / 9.13 ms | 97.0% |
| same | tier 2 | 4.77 / 7.39 / 8.59 / 9.28 ms | 91.5% |
| 1 Gbit/s, 2 ms, 1-BDP queue, shared | tier 2 | 0.65 / 1.40 / 1.71 / 2.18 ms | 0.3% |

The test sits above the noise of a link with no queue (the 11–12% it still reads as a queue is tier
2's own brake once it fills the link) and below what a shared queue shows at 10 ms. **It is blind
where a full queue is shorter than its floor:** at 1 Gbit/s and 2 ms a whole bandwidth-delay product of
queue is 2 ms of delay. There the loss signals below are the only guard, and the LAN arm proves them.

### Tier 2's response: no cut on a loss that is not congestion

| 200 Mbit/s, 10 ms, 1% loss | Vox | Cubic flow | Vox / Cubic |
|---|---|---|---|
| tier 1 | 57.3 | 61.7 | 0.93× |
| tier 2, cut to 0.85 on a no-queue loss | 63.3 | 62.7 | 1.01× |
| tier 2, no cut (run 1 / run 2) | 169.8 / 176.7 | 61.4 / 62.0 | **2.77× / 2.85×** |
| tier 2, no cut, with the loss trend below | 184.2 | 62.6 | **2.94×** |

At 8192-byte datagrams the window there is 100–130 KB, 12–16 packets; Cubic's congestion avoidance
regrows it by about half a packet per round trip (RFC 8312's `W_est` slope, 3(1−β)/(1+β) with
β = 0.7), and a loss arrives about every eight rounds. Any per-loss cut holds the rate down.

### Two loss guards for what the queue test cannot see

**The loss cap: 5% of the bytes sent over the last 8 rounds** (`GENTLE_LOSS_CAP`, `LOSS_ROUNDS`). Past
it, every loss is congestion. It is the guard for a **shallow buffer**, where congestion shows as loss
with almost no delay:

| 200 Mbit/s, 10 ms, ¼-BDP queue (62.5 KB, about 2.5 ms), shared | Vox | Cubic flow | Vox / Cubic | Vox's loss share |
|---|---|---|---|---|
| tier 1 | 38.3 | 38.1 | 1.00× | 3.10% |
| tier 2, no cap | 80.9 | 15.4 | **5.26×** | 35.61% |
| tier 2, 5% cap (40 s run / 80 s run) | 54.1 / 49.8 | 40.0 / 38.8 | **1.35× / 1.29×** | 4.34% / 4.57% |

With the cap the Cubic flow keeps what it gets against another Cubic (38.8–40.0 against 38.1), and in
the 80 s run every 10 s block stayed between 1.12× and 1.38×: tier 2 does not drift toward the cap.

**The loss trend: loss that grows with Vox's sending is congestion** (`LOSS_RISE_FACTOR` 1.5,
`TIER2_LOSS_RISE` 0.5 points, `TREND_BYTES` 32 MiB). On entering tier 2 the loss share of tier 1's
sending is recorded; once the share over the last 32 MiB sent passes max(1.5 × that, that + 0.5
points), every loss is congestion. Random loss does not move with Vox's rate (0.97–1.00% of what Vox
sent at 1% loss, in every tier); loss Vox causes does. It is the guard for a congested link whose
queue is too short to see and whose loss stays under the cap:

| 1 Gbit/s, 2 ms, 1-BDP queue (250 KB), shared | Vox | Cubic flow | Vox / Cubic | Vox's loss share |
|---|---|---|---|---|
| tier 1 | 448.6 | 489.7 | 0.92× | 0.39% |
| tier 2, queue test and cap only | 641.4 | 251.0 | **2.56×** | 2.16% |
| tier 2 with the trend over 8 rounds | 548.4 | 387.7 | 1.41× | 0.61% |
| tier 2 with the trend over 32 MiB | 548.3 | 335.4 | **1.63×** | 0.85% |

The window is 32 MiB, about four thousand datagrams, because over 8 rounds (a couple of hundred
packets) 1% random loss read above 1.5% by chance often enough to hold the 1%-loss arm to 1.62×.

### Tier 3: where it earns its place, and its trigger

At 1% loss tier 2 alone clears the decider's 2× (2.85–2.94×). Above the cap it cannot: every loss is
then congestion and tier 2 is Cubic.

| 200 Mbit/s, 10 ms | Controller | Vox | Cubic flow | Vox / Cubic | Vox's loss share |
|---|---|---|---|---|---|
| 5% random loss | tier 2, 5% cap (run 1 / 2) | 32.0 / 35.0 | 25.1 / 24.6 | 1.27× / 1.42× | 5.07% / 5.16% |
| 5% random loss | quinn's BBR (run 1 / 2) | 176.6 / 178.4 | 23.0 / 24.4 | **7.68× / 7.31×** | 5.04% / 5.01% |
| 1% random loss | `VoxBbr` held in tier 3 (fix-adr024-bbr, smoke) | 195.8 | 62.5 | 3.13× | 0.8–2.2% |
| ¼-BDP queue, shared | tier 2, 5% cap | 54.1 | 40.0 | 1.35× | 4.34% |
| ¼-BDP queue, shared | quinn's BBR | 154.6 | 21.4 | **7.22×, unfair** | 15.70% |

**The signal that shows tier 3 is needed: loss at or above the cap that does not grow with the rate.**
In tier 2 a 5%-loss Wi-Fi link and a shallow congested queue look alike (loss at the cap, no queue).
Sending harder separates them: random loss stays flat (5.07–5.16% under tier 2, 5.01–5.04% under BBR
at five times the rate); congestion loss climbs (4.34% to 15.70%). So tier 3 is to be entered on trial,
judged by the same trend test with a wider margin:

- **2 → 3 (a trial):** after tier 2's dwell, at least 20 rounds and 2 s in tier 2 with the loss share at or above the cap
  and no queue in any of those rounds. The loss share over the last 32 MiB is recorded as the trial's
  baseline. Tier 3 starts in BBR's steady state (ProbeBW) at the current delivery rate, round trip and
  window, never in Startup, whose 2.885× gain would breach the trial's bound.
- **Loss that grows leaves tier 3, at any time in it, not only during the trial:** the share over the last 32 MiB passes
  max(1.5 × the baseline, the baseline + 3 points). That is a failed trial.
- **Back-off after a failed trial:** tier 3 is barred for 30 s, doubled after each failed trial up to
  8 min, and reset to 30 s only after a stay in tier 3 of 5 min with no failure.
- **A queue leaves tier 3 (rule 3):** the last round's minimum round trip at or above
  `1.25 × max(base, window ÷ delivery rate) + 4 ms` (`TIER3_QUEUE_FACTOR`, `TIER3_QUEUE_MIN`), held
  for two rounds. Tier 3 has its own queue test because BBR stands a queue of its own: the tier-2 test
  threw it out within a second, every time, and with no other flow its rounds' minimum round trip
  was 18–38 ms on a 10.7 ms base (fix-adr024-bbr). `window ÷ delivery rate` is the round trip BBR's
  own data in flight explains; another flow's queue pushes the round trip past it.
- **How tier 3 paces.** quinn-proto 0.11 paces every connection from the window and the smoothed
  round trip; it never reads a controller's pacing rate (`pacing_rate` is reported in metrics only).
  So `VoxBbr`'s gains, including its probing cycle, are to act through its window alone, and its
  seeded rate is to drive sending as `window = rate × round trip`.
- **ECN marks and persistent congestion leave tier 3 at once,** with Cubic's reduction.
- **3 → 2 when the loss goes:** the loss share under half the cap (2.5%) for 40 rounds and 4 s, handed
  down to a `VoxCubic` seeded in congestion avoidance at the delivery rate × the base round trip.

**The trial's cost, plainly.** A trial on a path that turns out to be congested takes more than its
share from the competing flows for as long as it lasts: measured on the shallow queue, BBR took 7.22×
the Cubic flow. The rules bound that: each failed trial lasts until the 32 MiB trend window shows the
rise (32 MiB is about 1.5 s at the 176 Mbit/s BBR reached; up to about 3 s while the window still
holds tier 2's rounds), followed by at least 30 s of fair sharing, doubling with every
further failure to 8 min. So a competing flow loses its share for at most about 3 s in every 30 s, then
in every minute, then in every 8 minutes. That is the price of reaching 7× on a Wi-Fi link that loses
5% of its packets; R41's shallow-queue arm reports the worst 2 s window so the decider sees it.

### Tier 1 ↔ 2 and dwell

- **1 → 2:** at least 3 losses without a queue within 8 rounds, once tier 1's dwell (below) is over.
- **2 → 1:** no loss without a queue for 40 rounds and 4 s.
- **Dwell:** at least 2 s and 20 rounds in a tier before any switch, except rule 3.

### The changing link

Tier 2 with the cap (200 Mbit/s, 10 ms; 20 s clean, 20 s at 1% loss, 20 s clean, one transfer): 197.6,
173.8 and 197.5 Mbit/s per phase. In the second clean phase the half-second windows ran
169.1–226.8 Mbit/s (the lowest, 169.1, 18 s after the loss ended); the first three after the loss
ended carried 191.5, 184.6 and 198.8 Mbit/s.

### Not proven: no claim is made for these

ADR-024 makes **no claim** for the cases below; none is measured, and none is to be built for v0.2.10
(the decider, through vox, 2026-10-01). Where the design's behaviour can be reasoned, it errs safe:

- **Jittery links (cellular), bursty loss:** jitter that delays whole rounds reads as a queue, and a
  burst of losses trips the cap; either way tier 2 behaves as Cubic and tier 3 is not entered. These
  links are to gain nothing, not to be harmed. Not measured.
- **AQM (fq_codel, CAKE):** with flow queueing the router enforces fairness itself, and CoDel's early
  drops of the queue-builder raise Vox's own loss share, which the trend reads as congestion. Not
  measured.
- **Two or more competing flows, a 50 ms WAN shared link:** not measured.
- **Every threshold** rests on the runs above (one or two per row) at one link rate and round trip per
  case.

## Consequences

### Positive
- Clean links keep Cubic's measured ~98% of raw. Lossy links are to reach 2.9× a Cubic flow at 1% loss
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
    with a 1-BDP and a ¼-BDP queue, and at 1 Gbit/s, 2 ms with a 1-BDP queue, each judged over 60 s
    so tier-3 trials run inside it, with the worst 2 s window reported: Vox's rate is between **0.5×
    and 2×** the comparison flow's;
  - **changing**, clean → 1% loss → clean and clean → 5% loss → clean under one transfer: every second
    of each clean phase at the clean bar (90% of raw TCP on that clean link), back at it within 5 s of
    the loss ending, and the lossy phase at that loss's lossy-arm bar;
  - the existing **1 Gbit/s LAN** arm (at least 90% of raw) is the proof that a clean LAN is not held
    in a tier that slows it.

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
