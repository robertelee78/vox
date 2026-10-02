# ADR-024: Tapered Congestion Control

**Status**: **Accepted by the decider — 2026-09-25** (the direction and the shape below). **Built**
(M24.2–M24.4: `crates/vox-core/src/transport/{congestion,taper,vox_bbr}.rs` and R41's arms); M24.5 ships it in v0.2.10.
Planned for v0.2.10 (docs/release/v0.2.10.md). M24.1's design is "Signals and thresholds" below,
amended to the code as built.
**Date**: 2026-09-25
**Updated**: 2026-10-02 — the decider: ADR-024 guarantees speed only; fairness to other flows is a
non-goal, and every fairness gate and the tier-2 hold are withdrawn ("The goal: speed only").
2026-10-01 — M24.1: the decider's rulings of 2026-10-01, the signals and thresholds as measured on
today's tier 1, and the context restated from today's measurement. (Created 2026-09-25
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

### The goal: speed only

**The decider, 2026-10-02: ADR-024 guarantees speed only. Fairness to other flows is a non-goal:**
it is neither claimed nor gated. This supersedes the fairness rulings of 2026-10-01: the lossy
shared gate (a Cubic flow beside Vox on a lossy link keeps 90% of its solo rate), the joined arm (a
Cubic flow that starts beside a busy tunnel keeps that 90%), and the 2× upper bound on a congested
link are withdrawn. What ADR-024 guarantees, and what R41 gates:

1. **Faster on a lossy link:** at least 2× a Cubic flow on the same loss (the lossy arms).
2. **Never slower than the controller it replaces** on a clean, a congested and a changing link: the
   clean bar (90% of raw), and on a congested link at least 0.5× a Cubic flow sharing it.
3. **No stalls:** a switch between tiers does not stall the transfer.

Where this ADR's reasoning below says a mechanism keeps Vox fair, that is why it was built, not a
requirement; each such passage says so.

### The shape

**A tapered controller.** One Vox controller, a custom quinn `ControllerFactory`, holds three
tiers and move between them one tier at a time. **The taper goes both ways.** No change of QUIC
stack; quinn itself is not patched.

| Tier | Behaviour | Entered when |
|---|---|---|
| **1 — Cubic** | `VoxCubic`, as today: quinn-proto 0.11.18's Cubic with HyStart++ per RFC 9406 §4.2, restarted after idle. | Every connection starts here. A clean link never leaves. |
| **2 — Loss-aware Cubic** | `VoxCubic`, except that a loss the path signals do not call congestion costs **no** reduction (M24.1 measured that a smaller one is not enough). A loss with a queue, past the loss cap, past the loss trend, under persistent congestion or from an ECN mark costs Cubic's normal reduction. | From tier 1, when losses keep arriving without a queue. |
| **3 — BBR** | `VoxBbr`, a Vox-owned port of quinn-proto 0.11.18's BBR (the decider, 2026-10-01), so that a switch into it can be seeded with the current rate, which quinn's `BbrConfig` cannot be. | From tier 2, when the loss stays at or above tier 2's cap without a held queue: random loss heavier than tier 2 can carry. Left as soon as it is slower than tier 2 was. |

**Rules.**
1. **Climbing is one tier at a time, and only on sustained evidence** measured over many round trips,
   never on a single event.
2. **Descending is also one tier at a time** (tier 3 → 2 → 1) after a quiet stretch: no loss and no
   queue. Not "throughput holding": a rate measured on the connection cannot tell a slower path from
   a quieter application or from an older, faster path the connection ran on before (a 10 s best
   rate read 6.4 Gbit/s on a 200 Mbit/s link after a faster arm; fix-adr024-bbr). Each step is
   re-checked before the next.
3. **Tier 3 is kept only while it is faster.** Once it has dwelt, a 2 s delivered rate under 0.9× of
   tier 2's at the switch takes it back to tier 2, with a back-off before tier 3 may be entered again.
   (Until 2026-10-02 this rule left tier 3 on a queue, an ECN mark, persistent congestion or loss that
   grew with Vox's sending, to protect other flows; speed-only removed those exits.)
4. **No flapping.** Each tier has a minimum dwell time, and the thresholds to climb and to descend
   differ (hysteresis).
5. **A switch does not restart the connection's ramp.** The current rate and window are handed to
   the next tier, so moving between tiers does not cost a slow start. Unproven for speed: no arm is
   both lossy and long-RTT; the verifier's reset mutant (MUTANT-VER244-RESET) stayed green at 10 ms
   RTT, where BBR re-ramps within about a second.
6. **Security and consent are untouched.** This changes only the congestion controller, which runs
   inside quinn and sees no plaintext, keys or identities.

## Signals and thresholds (M24.1, measured 2026-10-01)

All three tiers read one helper, `PathSignals` in `crates/vox-core/src/transport/congestion.rs`, fed
from quinn's `Controller` callbacks; its names below are the constants it defines. Rounds are
counted in packet numbers (a round ends when a packet sent after it began is acknowledged), and
each acknowledgement's round-trip sample is its own `now - sent`.

### The comparison flow

**The comparison is TCP's algorithm (Cubic), run over the same simulated link; not kernel TCP, which
needs root to shape** (the decider, 2026-10-01, through vox: this stand-in counts as TCP for v0.2.10;
a race against real kernel TCP on Linux CI is optional, later). A kernel TCP connection cannot see an emulated loss
or share an emulated queue without root (dummynet or pf on macOS, netem on Linux), and Vox's agents
never run as root. So R41's comparison is a **quinn-Cubic flow**: a QUIC flow under quinn's
stock `CubicConfig` (RFC 8312), with QUIC's acknowledgement ranges for loss recovery, the tunnel's
8192-byte datagram ceiling and windows, crossing the same emulated link, the same loss draw and, on
the congested arms, the same queue. Cubic is what macOS TCP runs by default (`sysctl
net.inet.tcp.use_newreno` reads 0 on the Mac these were measured on) and what Linux runs by default.
**The speed claims are against RFC 8312 Cubic, not against any kernel's TCP.** Known differences:
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
sustained lateness does. So the emulator counts, each second, the share of the packets it
released at least 4 ms late, and an arm is CANNOT MEASURE when more than 10% of its judged seconds
had at least half their packets that late, as well as when any second ran more than 25 ms late (the
bound R41's raw-TCP links use). Every arm prints its per-second late share and which seconds
held a release 4 ms late. A bound on each second's latest release instead made the arms useless on a
machine doing ordinary work: in one run every 200 Mbit/s second held one (53 of 60 seconds of the
1-BDP congested arm), and arms went CANNOT MEASURE at a median of 5–6 ms, while the share of packets
released 4 ms late was 0.00–0.01 in every second of every arm at a load of 23–33 (the lead accepted
this rule, 2026-10-01). The tier-2 rows give the loss
trend the loss share the tier-1 run on the same link measured, as tier 2 takes it on entry.

### Base round trip (`BASE_RTT_WINDOW`, `SMALL_ROUND_BYTES`)

quinn's `RttEstimator::min` is the connection's lifetime minimum; in the spike it read 0 µs on a
connection that had first run unshaped, so every loss looked like a queue. A tunnel's connection
outlives the network it started on, so its base must expire. **Warm-up cost, measured:** for about
10 s after a path's round trip grows, the old base makes every loss read as congestion and Vox runs
at tier 1's rate; in tree A's 1%-loss run the tunnel ran 95–198 Mbit/s per half second after 10.5 s,
against the Cubic flow's 61.4. When the round trip shrinks, the base follows at once.

**But a windowed minimum alone drifts up under a standing queue.** A Cubic flow on a deep buffer
keeps its queue for as long as it sends and never drains it: fix-adr024-bbr's trace showed the 10 s
minimum reach 100–114 ms on a 10.6 ms link, after which overflow losses read as losses without a
queue and a clean link climbed to tier 2. A base that reads high turns congestion into "random" loss,
and a clean link climbs to tier 2; one that reads low only costs tier 2 its gain. So the base is the lower of
the 10 s minimum and the minimum of the latest **small round**: one that acknowledged at least two
packets and at most 32 KiB, which had no queue of its own behind it (slow start's first rounds, the
quiet moments between transfers). Two packets, because a peer acknowledges every second packet at
once but a lone one only when its delayed-acknowledgement timer fires, and these samples are
`now - sent`. The small round's value is replaced at the next small round, not kept as a minimum, so
a path whose round trip grows is followed at its next quiet moment. Not measured on its own; every
arm on the joint candidate ran with it.

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

**A round too small to time the path is no evidence of a queue** (`TIMED_ROUND_PACKETS`, 4). A peer
acknowledges a lone packet only when its delayed-acknowledgement timer fires (up to 25 ms), and each
sample is `now - sent`, so a round of one or two packets carries that delay in every sample: at tier
2's two-packet floor on the 6%-loss link the round minimum read 12.5 / 39.5 / 40.6 ms (p10 / p50 /
p90) on a 10.6 ms base, a queue in 62 of 84 rounds where there was none (fix-adr024-bbr's trace). A
round that acknowledged fewer than 4 packets gives no round minimum and no queue. Unproven for
speed: with the tier-2 hold gone, the misread no longer costs measurable throughput on any arm (a
mutant restoring it read 4.835× a Cubic flow on the 6% lossy arm, one run); kept because a false
queue reading is wrong input to every tier (the lead, 2026-10-02).

### Tier 2's response: no cut on a loss that is not congestion

| 200 Mbit/s, 10 ms, 1% loss | Vox | Cubic flow | Vox / Cubic |
|---|---|---|---|
| tier 1 (tree B) | 63.2 | 61.2 | 1.03× |
| tier 2 as designed: no cut, 5% cap, loss trend (tree B) | 191.1 | 59.9 | **3.19×** |
| tier 2, cut to 0.85 on a no-queue loss (tree A) | 63.3 | 62.7 | 1.01× |

At 8192-byte datagrams the window there is 100–130 KB, 12–16 packets (tree A's traces); Cubic's
congestion avoidance regrows it by about half a packet per round trip (RFC 8312's `W_est` slope,
3(1−β)/(1+β) with β = 0.7), and a loss arrives about every eight rounds. Any per-loss cut holds the
rate down, which is why tier 2 makes none.

**Tier 2 does not hold its window at a small queue** (withdrawn 2026-10-02). An earlier revision
held tier 2's growth once the last round's minimum round trip stood 0.5 ms (then 0.25 ms) or 5% (then
2.5%) of the base over it (`HOLD_DELAY_MIN`, `HOLD_DELAY_SHARE`), for the lossy shared gate: beside
tier 2 on a 1%-loss link, a Cubic flow kept 85.1% and 87.4% of its solo rate in two runs, under the
90% then required (fix-adr024-bbr's trace). The decider withdrew that gate on 2026-10-02, and the hold
cost speed where speed is gated: in one R41 run of the joint branch at 15fa0b54, which carried the
0.25 ms hold, Vox carried 30.8 Mbit/s beside a Cubic flow's 165.0 on the 1-BDP congested arm (0.19×)
and 16.0 against 36.4 on the ¼-BDP one (0.44×), both under the 0.5× floor (fix-adr024-bbr; tier 3,
which that commit also changed, is not entered on those arms, which carry no random loss). The hold
is removed. Without it, on the joint candidate 4b1d7808 (fix-adr024-bbr, one run each), the congested
arms read 1.015× (1-BDP), 1.014× (¼-BDP) and 1.695× (LAN-like).

### Two loss guards for what the queue test cannot see

Both guards were built to keep Vox fair on a congested link that its queue test cannot see, and the
tables below measure them against that. Since 2026-10-02 fairness is not a requirement; the guards
stay as built, because the cap is also tier 3's entry condition and the trend is tier 2's own
guard against loss it causes. Whether removing either would make Vox faster on a gated arm has not been measured.

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
1.75% + 0.5) = 2.63%): this is the arm where the trend sits at its trigger. The trend is judged over 32 MiB, about four
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
| ¼-BDP queue, shared | quinn's BBR (tree B; emulator up to 138 ms late, so smoke-grade) | 162.3 | 23.3 | **6.97×** | 13.00% |
| 1% random loss | `VoxBbr` held in tier 3 (fix-adr024-bbr, smoke; `runs/voxbbr/`) | 195.8 | 62.5 | 3.13× | — |

**The signal that shows tier 3 is needed: loss at or above the cap that does not grow with the rate.**
In tier 2 a 5%-loss Wi-Fi link and a shallow congested queue look alike (loss near the cap, no queue).
Sending harder separates them: random loss stays flat (5.37% under tier 2, 5.01% under BBR at six
times the rate); congestion loss climbs (4.59% to 13.00%). So tier 3 is entered when that loss holds and no queue does, and kept only while it is faster
(`crates/vox-core/src/transport/taper.rs`):

- **2 → 3:** at the cap, not below it (the decider, 2026-10-01: a link at exactly 5% is the
  boundary and may stay in tier 2, so R41's heavy-loss arms run at 6%, clearly past it). After tier
  2's dwell, the loss share over the last 32 MiB is at or above the cap (`GENTLE_LOSS_CAP`), through
  at least 20 rounds and 2 s (`CLIMB_3_ROUNDS`, `CLIMB_3_TIME`) in which no queue held for
  **8 rounds in a row** (`CLIMB_3_QUEUE_ROUNDS`). Not the 8-round share: it swung between 0.000 and
  0.143 at 5% random loss, so a streak of rounds at the cap never passed 7 of the 20 it needed
  (fix-adr024-bbr's trace, `runs/voxbbr/trace5.txt`). Not a queue of a round or two: on a lossy link
  tier 2 sends little, at 8 KB datagrams a round then holds one to four packets, and one delayed
  acknowledgement lifts a round's minimum past the queue test; rounds 4–7 ms over the base, two in a
  row about once a second, broke every 2-second streak and kept tier 3 out (1.25× a Cubic flow). The
  loss share is also the clean-LAN guard: a clean link loses only when its queue overflows, well
  under 1% of what it sends, so it never reaches tier 3.
- **Tier 3 starts in BBR's steady state (ProbeBW), never in Startup**, whose 2.885× gain overshoots
  a path whose capacity tier 2 has already shown. It is seeded with tier 2's window over its smoothed
  round trip as its rate, the base round trip (`PathSignals::min_rtt`) and tier 2's window: not a best rate kept from earlier, which
  can belong to another path (6.4 Gbit/s read on a 200 Mbit/s link; fix-adr024-bbr). BBR's own
  delivery-rate samples raise a seed that is low within a few rounds.
- **Tier 3 is left when it is slower than tier 2 was** (`TIER3_SLOWER` 0.9, `RATE_WINDOW` 2 s).
  ADR-024 guarantees speed only (the decider, 2026-10-02): tier 3 exists to be faster and is kept
  only while it is. Vox's delivered rate over the last 2 s is recorded at 2 → 3; once tier 3 has
  dwelt, a round whose rate over the same window is under 0.9× of it takes the connection back to
  tier 2. Tier 3 is entered only when no such back-off is running. The exit is judged only when no
  application-limited round fell within the last 2 s: a transfer that pauses is not a slower tier 3.
  Unproven for speed: a mutant without this guard stayed green on the 6% paused arm, because
  application-limited rounds are already skipped; it guards an application that sends below the
  window without quinn marking its rounds application-limited.
- **Back-off after such an exit:** tier 3 is locked out for 30 s (`BACKOFF_FIRST`), doubled after each
  further exit up to 8 min (`BACKOFF_MAX`), and reset to 30 s only after a stay in tier 3 of 5 min
  (`BACKOFF_RESET`) without one.
- **3 → 2 when the loss goes:** after tier 3's dwell, the loss share over the last 8 rounds under
  half the cap (2.5%) for 40 rounds and 4 s (`QUIET_ROUNDS`, `QUIET_TIME`); no back-off follows. These
  two are tier 3's only exits. Both hand down to a loss-aware `VoxCubic` seeded in congestion
  avoidance at BBR's delivery rate × the base round trip (`PathSignals::min_rtt`).
- **Removed (2026-10-02):** earlier designs also left tier 3 on a queue (rule 3, with its own
  delay test), on a loss share that rose with Vox's sending (the trial and its whole-stay check), and
  on an ECN mark or persistent congestion. Those protected other flows; fairness is not ADR-024's to
  guarantee, and they are not in the code.
- **How tier 3 paces.** quinn-proto 0.11 paces every connection from the window and the smoothed
  round trip; it never reads a controller's pacing rate (`pacing_rate` is reported in metrics only).
  So `VoxBbr`'s gains, including its probing cycle, act through its window alone. Its window is
  quinn's: twice the estimated bandwidth-delay product plus the acknowledgement aggregation measured
  (option A, `K_DERIVED_HIGH_CWNDGAIN` 2.0). A window of one bandwidth-delay product with no
  aggregation allowance (option C) cost 7.4% of tier 3's speed with Vox alone on a 6%-loss, 4-BDP
  link (182.1 against 196.7 Mbit/s; fix-adr024-bbr's spike, one run each), and ADR-024 guarantees
  speed only.
- **`VoxBbr` is quinn-proto 0.11.18's BBR ported into Vox** (`crates/vox-core/src/transport/vox_bbr.rs`;
  quinn is not patched). It departs from quinn's in two estimators, which is why quinn's ran a clean
  LAN at 28%: its minimum round trip is BBR's own 10 s windowed minimum (quinn's read
  `RttEstimator::min`, the lifetime minimum, 0 µs in the spike), and its bandwidth estimate is the BBR
  draft's delivery-rate sampling with every sample fed to the 10-round max filter (quinn's never
  decayed an overshoot). quinn reports a batched (GSO) send as one `on_sent` but acknowledges each
  packet in it, so a send's record stays until a packet sent after it is acknowledged, and every
  packet of a batch gives a rate sample. The gain cycle's random offset is drawn with `getrandom`.
  Measured with tier 3 held, through the shipped binary: a clean 1 Gbit/s, 2 ms LAN at 962, 962 and
  940 Mbit/s against tier 1's 983, 988 and 983; a 200 Mbit/s, 10 ms link at 1% loss at 195.8 against
  a Cubic flow's 62.5, 3.13× (`runs/voxbbr/lan-bbr.log`, `lan-taper.log`, `lossy-bbr.log`).

**What a tier-3 stay costs other flows, recorded and not gated.** BBR does not back off on loss, so
on a path that is in fact congested tier 3 takes more than its share for as long as it stays: on
the shallow queue quinn's BBR took 6.97× the Cubic flow. The exit above leaves only when Vox itself
gets slower. ADR-024 makes no claim about a competing flow's rate (the decider, 2026-10-02).

### An idle restart: the tier resets, the tier-3 back-off survives

`IdleRestart` starts a fresh controller after the connection sends nothing for `IDLE_RESTART` (1 s)
and several round trips, because the path may have changed. The tier and the 10 s base round trip
reset with it: the next transfer starts in tier 1 and climbs again (at least the 2 s dwell,
then three losses without a queue). The tier-3 lockout survives it (`Tier3Backoff`): a tier 3 that was
slower stays locked out across a pause. R41's "paused" arm (the 1%-loss link, a 3 s pause)
shows the speed a person sees after the pause.

### Tier 1 ↔ 2 and dwell

- **1 → 2:** once tier 1's dwell (below) is over, all of: at least 3 losses of either kind (with or
  without a queue) in the last 8 rounds (`CLIMB_1_LOSSES`, `CLIMB_1_ROUNDS`); at least the last 8
  rounds (`CLIMB_1_ROUNDS`) in each of which no queue had been held for 8 rounds in a row
  (`CLIMB_3_QUEUE_ROUNDS`); and the loss share
  over the last 32 MiB at least 0.5% (`TIER2_ENTRY_SHARE`). Losses of either kind, because past the
  5% cap every loss is called congestion: counting only losses without a queue held Vox in tier 1
  for 18 s and more on the changing 6% arm, climbing only when the share happened to dip
  (fix-adr024-bbr's trace). A mutant that restores the old count is red in R41's full sequence (one
  run): the 6% paused arm stayed near 20 Mbit/s for 21 s after the resume, and the 1% lossy arm read
  1.596×; the 6% lossy arm itself stayed green in that run (10.257×). The loss share itself is exact: on the 6% arm Vox's own lost-over-sent
  read 0.0594 against the emulator's 0.0594 of bytes dropped at random, and the 32 MiB trend
  varies by about 0.35 points (one standard deviation, about 4,000 datagrams) around it. That share is
  tier 2's loss baseline, and it follows the trend up (never down) until tier 2 has sent 32 MiB of
  its own, then holds. Without the 0.5%, a link that turned lossy mid-transfer entered tier 2 with
  a baseline drawn from its clean history (about 0.1%), its random loss then read as loss that grew,
  and tier 2 cut like Cubic (fix-adr024-bbr's changing-arm trace: 57 Mbit/s through a 1% phase tier 2
  carries at about 180).
- **2 → 1:** after tier 2's dwell, no loss and no queue in each of 40 rounds spanning 4 s
  (`QUIET_ROUNDS`, `QUIET_TIME`). Tier 2's loss baseline is cleared.
- **Dwell:** at least 2 s and 20 rounds in a tier before any switch (`DWELL_TIME`, `DWELL_ROUNDS`).

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
  cap with no held queue meets tier 3's entry condition, so such a link can enter tier 3; it leaves
  if tier 3 is slower there.
- **AQM (fq_codel, CoDel, CAKE):** early drops at a short queue may read as random loss; whether the
  loss trend catches them, and how flow queueing changes the outcome, is unmeasured.
- **Two or more competing flows, and a shared 50 ms WAN link:** unmeasured.
- **Every threshold** rests on the runs above (one or two per row) at one link rate and round trip per
  case.
- **N1, a tier 3 judged against an old rate:** the "slower" exit compares tier 3 with tier 2's rate
  before the switch. If a lossy link's capacity falls while Vox is in tier 3, tier 3 can be slower
  than tier 2 was yet faster than tier 2 would now be; Vox then drops to tier 2 and is locked out of
  tier 3 for 30 s, doubling to 480 s. It is never slower than the controller it replaces, which has
  no tier 3.
- **N3, datagram size:** every threshold was measured with Vox's 8192-byte datagrams
  (`MAX_UDP_PAYLOAD`), at 200 Mbit/s with 10 ms and 400 Mbit/s with 2 ms. A path limited to
  1200-byte datagrams is unmeasured, and the figures that count packets or bytes
  (`TIMED_ROUND_PACKETS`, `CLIMB_3_QUEUE_ROUNDS`, `TREND_BYTES`) shift with datagram size.

## Consequences

### Positive
- Clean links keep Cubic's speed: the clean LAN-like arm read 396.4 Mbit/s against a 347.4 bar (90%
  of raw). Lossy links run 2.929× a Cubic flow at 1% loss and 9.210× at 6% (joint candidate
  4b1d7808, fix-adr024-bbr, one run each, `runs/m243-m244/speed-4b1d7808.log`), without paying BBR's
  cost where it hurts. The full R41 on c4 (`eb15a78c`, one run, `runs/m243-m244/full-c4-eb15a78c.log`)
  read 3.165× at 1% and 9.978× at 6%, the 1 Gbit/s LAN and WAN links at 102.9% of raw, and every
  changing and paused arm at its bars; its clean LAN-like and shallow congested arms were CANNOT
  MEASURE (calibration 93.4%; emulator 29 ms late).
- It stays on quinn 0.11; tier 1 and tier 3 are Vox's ports of quinn's own controllers, and quinn
  is not patched. One dependency is added directly, `tracing` (default features off, `std`), which
  quinn already brings in: each tier switch emits `tracing::debug!` under the target
  `vox::congestion`, and nothing prints by default.

### Negative
- Loss differentiation can misread congestion as random loss. If it does, Vox sends harder than a
  Cubic flow would and can take a competing flow's share; ADR-024 accepts that (fairness is a
  non-goal, 2026-10-02), and it is measured: on c4 (`eb15a78c`), sharing the 1-BDP congested link Vox
  carried 192.9 Mbit/s and the Cubic flow 3.1 (62.2×), and on the LAN-like one 361.8 against 22.0
  (16.4×), where on `4b1d7808` the same arms read 1.015× and 1.695×. The likely cause, not traced:
  since 1 → 2 counts losses with a queue too, a congested link's overflow losses take Vox up the
  tiers as random loss does. The opposite
  misreading, congestion handling that leaves Vox slower than the controller it replaces, is what
  R41's congested arms gate, at a deep, a shallow and a LAN-length queue.
- A tier-3 stay on a path that is in fact congested takes competing flows' share for as long as it
  lasts (above); accepted.
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
  APPARATUS (emulator late by the rule under "Method", the tunnel's bytes not crossing the emulated
  link, comparison flow not running), an APPARATUS fault ending only its own arm:
  - **lossy**, 200 Mbit/s, 10 ms, at 1% and at 6% random loss (6%, clearly past tier 2's 5% cap: the
    decider, 2026-10-01): Vox carries at least **2×** the
    quinn-Cubic comparison flow on the same loss;
  - **congested**, the link shared with the comparison flow through one queue, at 200 Mbit/s, 10 ms
    with a 1-BDP and a ¼-BDP queue, and at 400 Mbit/s, 2 ms with a 1-BDP queue (a full queue there is
    2 ms, under the queue test's floor), each judged over 60 s
    so a tier-3 stay runs inside it (the 2 s windows printed as DIAGNOSTIC only): Vox's rate is at least
    **0.5×** the comparison flow's, never slower than the controller it replaces; there is no upper
    bound (2026-10-02);
  - **changing**, clean → 1% loss → clean and clean → 6% loss → clean under one transfer, 30 s per
    phase so the 6% phase spans the climb to tier 3: every 2 s window of each clean phase at the clean
    bar (90% of raw TCP on that clean link), back at it within 5 s of the loss ending, and the lossy
    phase at that loss's lossy-arm bar; a red names its phase (CLEAN, LOSSY or RECOVERY) and prints
    the per-second series;
  - **no stall** (the decider's third speed gate, 2026-10-02), on the lossy and the changing arms: no
    2 s window of Vox's falls under **0.5×** the Cubic flow's mean rate on the same loss
    (`STALL_FLOOR`), judged from the first lossy second with no settle allowance (on the lossy arms
    from the stream's second second, the settle included; on the changing arms over the whole lossy
    phase). A tier switch that stalls a transfer, or a tier stuck at its floor, shows here even where
    the run's mean clears the bar;
  - **paused**, the 1%- and the 6%-loss link with a transfer that stops for 3 s (longer than
    `IDLE_RESTART`) and resumes: back at the lossy bar within 8 s at 1% and within 20 s at 6%
    (`TIER3_WITHIN`), and its mean past that at the bar;
  - **tier 3 within 20 s** (`TIER3_WITHIN`), on the 6% lossy, changing and paused arms: the first 2 s
    window at the lossy bar (2× the Cubic flow) ends within 20 s of the loss starting or the transfer
    resuming, so a late climb cannot pass on the mean. Healthy climbs reached it at 5–12 s and the
    defect at 18–29 s; 20 s, not 15, so as not to fit the bound to one sample;
  - **clean LAN-like**, 400 Mbit/s, 2 ms: every one of 30 seconds at the clean bar (90% of raw), the
    proof that a clean link is not held in a tier that slows it. 400 Mbit/s because the userspace
    emulator calibrates that rate on a machine doing ordinary work; R41's 1 Gbit/s LAN link often
    cannot (its weakest calibration window read 78.8%, 75.6% and 82.5% in three runs at load 38–66,
    where each must reach 95%: `runs/r41/`), and stays as it is.

  Withdrawn 2026-10-02 (fairness is a non-goal): the **lossy shared** arm (the comparison flow keeps
  90% of its solo rate beside Vox on a 1%- and a 6%-loss link), the **joined** arm (the same, for a
  flow that starts while the tunnel is busy on a 6%-loss, 4-BDP link), and the congested arms' 2×
  upper bound. For the record only: adr-020_adr-021's GREEDY mutant (Vox never backs off on loss)
  read 70.5×, 151× and 5,196× the comparison flow on the 1-BDP, ¼-BDP and LAN-like congested arms (on
  M24.2 c2 5607a58c, #155), which that bound turned red; with no upper bound it gates nothing.

  The lossy arms are red on tier 1 alone (1.047× and 1.071× on M24.2 c3.1, `0b7d4d0d`). R41's watchdog budget is 1800 s, because the arms
  take about ten minutes (at 600 s it aborted a run that had measured every arm; the lead accepted
  this, 2026-10-01).
- **M24.3 — Tier 2** (loss-aware Cubic) with the queue test, the cap and the trend, proved on all arms.
- **M24.4 — Tier 3** (`VoxBbr`) with its entry, the speed exit and back-off, both-way transitions,
  hysteresis and rate hand-off,
  proved on all arms.
- **M24.5 — Ship.**
  - Acceptance (the decider, 2026-10-02: speed only): LAN and WAN unchanged against raw (at least
    90%); on each lossy arm Vox carries at least 2× the comparison flow; on each congested arm Vox's
    rate is at least 0.5× the comparison flow's; the changing arms hold as M24.2 states; and no
    switch between tiers stalls a transfer. The post
    says, for each arm, what it shows with tier 3 on and off.
  - Every proof drives the shipped binary and is mutation-checked. R41 is an optional proof
    (cargo feature `optional-proofs`, #301's sort delta `90cbb071`): it blocks nothing, and the
    verifier runs it.

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
