# ADR-024: Tapered Congestion Control

**Status**: **Accepted by the decider — 2026-09-25** (the direction and the shape below). **Not built.**
Scheduled after v0.2.9. Milestones M24.1–M24.5 below; none is done.
**Date**: 2026-09-25
**Updated**: 2026-09-25 — created from the decider's decision on PRD-001 R41's lossy-link arm.
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

**Measured, 2026-09-25, all in one R41 window** (same machine, same emulator, share of raw TCP over
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
| **2 — Loss-aware Cubic** | Cubic, but a loss that arrives **without** a rise in delay (no queue building) causes only a small reduction. A loss with rising delay causes Cubic's normal reduction. | From tier 1, when losses keep arriving without a delay rise. |
| **3 — BBR** | quinn's `BbrConfig`. On random loss it matched noq's BBRv3 (21.4% vs 18.5%), so no stack change is needed. | From tier 2, when throughput stays well below the delivery rate the path has already shown, for a sustained number of round trips. |

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

## Consequences

### Positive
- Clean links keep Cubic's measured ~98% of raw. Lossy links can reach what BBR measured, about 4×,
  without paying BBR's cost where it hurts.
- No dependency change. It stays on quinn 0.11 and quinn's own controllers.

### Negative
- Loss differentiation can misread heavy cross traffic as random loss. If it does, Vox sends harder
  than is fair on a congested link. The guard (rule 3) and the fairness arm (M24.2) exist for this.
- It is a new controller that Vox must maintain, with its own thresholds to tune.

### Neutral
- If quinn later ships a BBR that holds a clean LAN, tier 3 can adopt it without changing the shape.

## Milestones

- **M24.1 — Design.** State the exact signals and thresholds: the delay-rise test, the "well below the
  path's delivery rate" test, dwell times and hysteresis. Reviewed by gpt-6-astra, glm-5.3, kimi-k3
  and codex, against quinn-proto's `Controller` trait (0.11.14) and the prior art above.
- **M24.2 — Gate arms first.** Add two R41 arms before any controller code:
  - a congested link shared with competing flows, where Vox must share fairly;
  - a link that changes mid-transfer (clean → 1% loss → clean), where Vox must climb, then taper back
    down tier by tier to Cubic at full rate, without flapping.

  Both must be red, or report the problem, on today's Cubic where it applies.
- **M24.3 — Tier 2** (loss-aware Cubic) with the delay-rise guard, proved on all arms.
- **M24.4 — Tier 3** (BBR) with both-way transitions, hysteresis and rate hand-off, proved on all arms.
- **M24.5 — Ship.**
  - Acceptance: LAN and WAN unchanged against Cubic; the lossy arm far above ~5%; fair on the
    congested arm; transitions correct and non-flapping on the changing arm.
  - Every proof drives the shipped binary and is mutation-checked.

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
