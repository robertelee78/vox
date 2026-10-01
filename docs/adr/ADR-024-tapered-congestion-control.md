# ADR-024: Tapered Congestion Control

**Status**: **Accepted by the decider — 2026-09-25** (the direction and the shape below). **Not built.**
Planned for v0.2.10 (docs/release/v0.2.10.md). M24.1's design is below ("Signals and thresholds");
M24.2–M24.5 are to be built.
**Date**: 2026-09-25
**Updated**: 2026-09-25 — created from the decider's decision on PRD-001 R41's lossy-link arm.
2026-10-01 — M24.1: the decider's rulings of 2026-10-01 (acceptance as a fair race, a Vox-owned BBR,
all three tiers built, the changing arm judged by user-visible speed); signals and thresholds
measured on the current tier 1; the context table restated from today's measurement.
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: transport, quic, congestion-control, throughput, wireless

## Context

PRD-001 R41 says a Vox tunnel **must not throttle the network it runs over**. The decider's standing
direction for throughput is *"as fast as possible, while still retaining our other goals/security"*.
R41 is measured by `perf_r41_tunnel_throughput_proof` over emulated links: raw TCP and a Vox tunnel
cross the same shaper.

The congestion controller is quinn's default, **Cubic**. Cubic treats every lost packet as a sign of
congestion and cuts its sending rate. On a link that loses packets for reasons other than
congestion, such as Wi-Fi interference, that is the wrong answer: the tunnel slows down for a network
that has spare capacity.

**Measured, 2026-09-25, all in one R41 window** (superseded below by the 2026-10-01 measurement; kept
as the record of why BBR was not made the default) (same machine, same emulator, share of raw TCP over
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

**Measured again, 2026-10-01** (M24.1 spike, one run each, release build of the shipped binary,
under the shared timing lock at a load of about 80; the emulator ran at most 18 ms late, typically
2–6 ms). Since 2026-09-25 tier 1 is `VoxCubic` (quinn 0.11.18's Cubic with HyStart++ and a restart
after idle) and Vox sends 8192-byte datagrams. The comparison is no longer raw TCP behind a proxy,
which never sees the link's loss, but a flow running TCP's algorithm over the same lossy link (see
"The comparison flow" below). Rates are means over the judged seconds.

| Link (200 Mbit/s, 10 ms RTT) | Vox, today's tier 1 | Cubic flow, same link | Vox / Cubic |
|---|---|---|---|
| 1% random loss | 57.3 Mbit/s (29% of the link) | 61.7 Mbit/s | **0.93×** |
| 5% random loss | — | 23.0–25.1 Mbit/s | — |
| shared with the Cubic flow, 1-BDP queue | 98.8 Mbit/s | 97.4 Mbit/s | 1.01× |
| shared with the Cubic flow, ¼-BDP queue | 38.3 Mbit/s | 38.1 Mbit/s | 1.00× |

The 4.5% figure of 2026-09-25 is stale: with 8192-byte datagrams the same 1% loss costs far fewer
reductions per byte. Today's Vox matches a Cubic flow on a lossy link; the decider's bar is twice it.

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

**A tapered controller.** One Vox controller, a custom quinn `ControllerFactory`, holds three tiers
and moves between them one tier at a time. **The taper goes both ways.** No change of QUIC stack.

| Tier | Behaviour | Entered when |
|---|---|---|
| **1 — Cubic** | quinn's Cubic, unchanged | Every connection starts here. A clean link never leaves. |
| **2 — Loss-aware Cubic** | Cubic, but a loss that arrives **without** a queue behind it does not reduce the window (M24.1 measured that a small reduction is not enough; see below). A loss with a queue, past the loss cap, persistent congestion or an ECN mark causes Cubic's normal reduction. | From tier 1, when losses keep arriving without a delay rise. |
| **3 — BBR** | `VoxBbr`: a Vox-owned port of quinn 0.11.18's BBR (the decider, 2026-10-01: "port it into Vox"), so that a switch into it is seeded with the current rate, which quinn's `BbrConfig` cannot be. quinn itself is not patched. | From tier 2, **on trial**, when the loss stays above tier 2's cap with no queue (random loss heavier than tier 2 can carry). |

**Rules.**
1. **Climbing is one tier at a time, and only on sustained evidence** measured over many round trips,
   never on a single event.
2. **Descending is also one tier at a time** (tier 3 → 2 → 1) after a quiet stretch: no loss, and
   throughput holding. Each step is re-checked before the next.
3. **Congestion is the one exception.** A rise in delay (a queue building) takes tier 3 **at once** to
   tier 2, which already backs off on delay. From there the taper continues normally. BBR is the tier
   that fails on a clean or congested path, so it must never be the tier holding one.
4. **No flapping.** Each tier has a minimum dwell time, and the thresholds to climb and to descend
   differ (hysteresis).
5. **A switch does not restart the connection's ramp.** The current rate and window are handed to
   the next tier, so moving between tiers does not cost a slow-start.
6. **Security and consent are untouched.** This changes only the congestion controller, which runs
   inside quinn and sees no plaintext, keys or identities.

## Signals and thresholds (M24.1, measured 2026-10-01)

All three tiers read one helper, `PathSignals` in `vox-core/src/transport/congestion.rs`, fed from
quinn's `Controller` callbacks. Rounds are counted in packet numbers (a round ends when a packet sent
after it began is acknowledged). Each acknowledgement's round-trip sample is its own `now - sent`.

**The comparison flow.** The decider asked for a fair race against TCP. A kernel TCP connection
cannot see an emulated loss or share an emulated queue without root (dummynet or pf on macOS, netem
on Linux), and Vox's agents never run as root. So R41's comparison flow is **TCP's algorithm on the
same link**: a QUIC flow under quinn's stock Cubic (RFC 8312, the default of macOS and Linux TCP)
with QUIC's selective acknowledgements (the loss recovery of a modern SACK TCP), crossing the same
emulated link, the same loss and, on the congested arms, the same queue. A userspace TCP without
SACK recovery (smoltcp) would lose far more than real TCP at 1% loss and flatter Vox.

**Base round trip: a 10 s windowed minimum** (`BASE_RTT_WINDOW`). quinn's `RttEstimator::min` is the
connection's lifetime minimum; in the spike it read 0 µs on a connection that had first run
unshaped, so every loss looked like a queue. A tunnel's connection outlives the network it started
on, so its base round trip must expire. Consequence, measured: for 10 s after the path's round trip
grows, losses read as congestion and Vox runs at tier 1's rate; R41's arms settle 12 s before they
judge.

**A queue is building** when the last finished round's **minimum** round trip exceeds the base by at
least `max(4 ms, 40% of the base)` (`QUEUE_DELAY_MIN`, `QUEUE_DELAY_SHARE`). A round's minimum, not
the smoothed round trip: one delayed acknowledgement must not read as a queue. Measured at each loss:

| Link | rise over the base at a loss: median / 90th / 99th percentile |
|---|---|
| 1% random loss (no loss is congestion) | 2.2 / 4.3 / 9.0 ms |
| shared, 1-BDP queue (loss is congestion) | 7.4 ms median, 4.7 ms 10th percentile |

The threshold sits above the noise of a link with no queue (12% of its losses still read as
congestion, which is tier 2's own brake once it fills the queue) and below what a shared queue
shows.

**Tier 2's response: no cut on a loss without a queue.**

| 200 Mbit/s, 10 ms, 1% loss | Vox | Cubic flow | Vox / Cubic |
|---|---|---|---|
| tier 1 (today) | 57.3 | 61.7 | 0.93× |
| tier 2, cut to 0.85 on a no-queue loss | 63.3 | 62.7 | 1.01× |
| tier 2, no cut on a no-queue loss | 169.8 (170–198 once the base window cleared) | 61.4 | **2.77×** |

With 8192-byte datagrams the window is about 15 packets, Cubic regrows about a quarter of a packet
per round trip, and a loss arrives every ten or so round trips: any per-loss cut holds the rate.

**The loss cap: 5% of the bytes sent over the last 8 rounds** (`GENTLE_LOSS_CAP`, `LOSS_ROUNDS`). Past
it, every loss is congestion. This is the guard for a **shallow buffer**, where congestion shows as
loss with no measurable delay. Measured, sharing a 200 Mbit/s, 10 ms link with a Cubic flow:

| Queue | Controller | Vox | Cubic flow | Vox / Cubic | Vox's loss share | tail drops |
|---|---|---|---|---|---|---|
| 1 BDP (250 KB) | tier 1 | 98.8 | 97.4 | 1.01× | — | 417 |
| 1 BDP | tier 2, no cap | 105.2 | 91.6 | 1.15× | 0.2% | — |
| ¼ BDP (62.5 KB, about 2.5 ms) | tier 1 | 38.3 | 38.1 | 1.00× | 3.1% | 1,574 |
| ¼ BDP | tier 2, no cap | 80.9 | 15.4 | **5.26×** | 35.6% | 44,101 |
| ¼ BDP | tier 2, 5% cap | 54.1 | 40.0 | **1.35×** | 4.3% | 2,338 |

With the cap the Cubic flow keeps what it gets against another Cubic (40.0 against 38.1). Random
loss on the Wi-Fi-like link was 1.0% of what Vox sent, well under the cap.

**Tier 3: where it earns its place, and its trigger.** At 1% loss tier 2 alone clears the decider's
2× (2.77×). Above the cap it cannot: every loss is then congestion and tier 2 is Cubic.

| 200 Mbit/s, 10 ms | Controller | Vox | Cubic flow | Vox / Cubic | Vox's loss share |
|---|---|---|---|---|---|
| 5% random loss | tier 2, 5% cap | 32.0 | 25.1 | 1.27× | 5.07% |
| 5% random loss | quinn's BBR | 176.6 | 23.0 | **7.68×** | 5.03% |
| ¼-BDP queue, shared | tier 2, 5% cap | 54.1 | 40.0 | 1.35× | 4.3% |
| ¼-BDP queue, shared | quinn's BBR | 154.6 | 21.4 | **7.22×, unfair** | 15.7% |

**What signal shows tier 3 is needed: loss at or above the cap that does not grow with the rate.**
In tier 2 a 5%-loss Wi-Fi link and a shallow congested queue look alike (loss share at the cap, no
queue). Sending harder separates them: random loss stays flat (5.07% at 32 Mbit/s, 5.03% at
177 Mbit/s), congestion loss climbs (4.3% to 15.7%). So tier 3 is entered on trial:

- **2 → 3 (trial):** for at least 20 rounds and 2 s in tier 2: loss share ≥ the cap, no queue in any
  of those rounds, and the delivery rate below 50% of the best of the last 10 s. The loss share at
  that moment is recorded.
- **Trial fails → 2 at once:** within the first 20 rounds and 2 s of tier 3, the loss share rises
  above `max(1.5 × the entry share, the entry share + 3 points)`. Tier 3 is then barred for a back-off
  of 30 s, doubled after each failed trial up to 8 min, reset after 5 min without one. A competing
  flow pays at most 2 s of an unfair share per trial.
- **3 → 2 on a queue, at once (rule 3):** a queue building for 2 rounds.
- **3 → 2 when the loss goes:** loss share below half the cap (2.5%) for 40 rounds and 4 s, handed
  down to a Cubic seeded at `delivery rate × base round trip`.

**Tier 1 ↔ 2** (unchanged from the draft, to be confirmed on the changing arm):
- **1 → 2:** at least 3 losses without a queue within 8 rounds, after at least 1 s in tier 1.
- **2 → 1:** no loss without a queue for 40 rounds and 4 s.
- **Dwell:** at least 2 s and 20 rounds in a tier before any switch except rule 3 and a failed trial.

**The changing link, tier 2 with the cap** (200 Mbit/s, 10 ms; 20 s clean, 20 s at 1% loss, 20 s
clean, one transfer): 197.6, 173.8 and 197.5 Mbit/s per phase, back at full rate within a second of
the loss ending.

## Consequences

### Positive
- Clean links keep Cubic's measured ~98% of raw. Lossy links can reach what BBR measured, about 4×,
  without paying BBR's cost where it hurts.
- No dependency change. It stays on quinn 0.11 and quinn's own controllers.

### Negative
- Loss differentiation can misread heavy cross traffic as random loss. If it does, Vox sends harder
  than is fair on a congested link. The guards are the queue test, the 5% loss cap (measured on a
  shallow buffer, above), the trial entry to tier 3, and rule 3; the congested arms (M24.2), at a
  deep and a shallow buffer, prove them.
- For 10 s after a path's round trip grows, the old base round trip makes every loss read as
  congestion: Vox runs at tier 1's rate until it expires.
- It is a new controller that Vox must maintain, with its own thresholds to tune.

### Neutral
- If quinn later ships a BBR that holds a clean LAN, tier 3 can adopt it without changing the shape.

## Milestones

- **M24.1 — Design.** State the exact signals and thresholds: the delay-rise test, the "well below the
  path's delivery rate" test, dwell times and hysteresis. Reviewed by gpt-6-astra, glm-5.3, kimi-k3
  and codex, against quinn-proto's `Controller` trait (0.11.18) and the prior art above. The numbers
  are in "Signals and thresholds" above.
- **M24.2 — Gate arms first.** R41's arms, driven through the shipped binary, judged by the speed a
  person sees (the decider, 2026-10-01: never by asserting which tier is running), each red naming
  PRODUCT or APPARATUS (emulator late, comparison flow not running):
  - **lossy**, 200 Mbit/s, 10 ms, 1% loss, and the same at 5% loss: Vox carries at least **2×** the
    Cubic comparison flow on the same loss;
  - **congested**, the same link shared with the Cubic flow through one queue, at 1 BDP and at ¼ BDP:
    Vox's rate is between **0.5× and 2×** the Cubic flow's;
  - **changing**, clean → 1% loss → clean under one transfer: every second of each clean phase at the
    clean bar (90% of raw TCP on that clean link), back at it within 5 s of the loss ending, and the
    lossy phase at the lossy arm's bar.

  The lossy arm is to be red on today's tier 1 (0.93× measured).
- **M24.3 — Tier 2** (loss-aware Cubic) with the delay-rise guard, proved on all arms.
- **M24.4 — Tier 3** (BBR) with both-way transitions, hysteresis and rate hand-off, proved on all arms.
- **M24.5 — Ship.**
  - Acceptance (the decider, 2026-10-01, "fair race, clear win"): LAN and WAN unchanged against raw
    (at least 90%); on each lossy arm Vox carries at least 2× the Cubic comparison flow on the same
    loss; on each congested arm Vox's rate is between 0.5× and 2× of the competing Cubic flow's; on
    the changing arm the user-visible speed holds in each phase as M24.2 states. The post says, for
    each arm, what it shows with tier 3 on and off.
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
