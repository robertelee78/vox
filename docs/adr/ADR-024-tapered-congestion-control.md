# ADR-024: Tapered Congestion Control

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted by the decider, 2026-09-25. Speed only, 2026-10-02. **Built on this tree**:
M24.1–M24.5 (#154–#158, all closed). The code is `crates/vox-core/src/transport/congestion.rs`
(`VoxCubic`, `PathSignals`, `IdleRestart`), `taper.rs` (the tier switch) and `vox_bbr.rs`
(`VoxBbr`). `quic.rs` installs `IdleRestartConfig`, which wraps `taper::Tapered`, on every
connection. Receiver overflow (RO-1–RO-7) is `overflow.rs`, `crates/vox-sockdrops`, and the skip
and undo in `taper.rs`. The proof is `perf_r41_tunnel_throughput_proof`, its ADR-024 arms
(`taper_arms`) and its R41a arm.
Not built: no race against kernel TCP (TC-2). The cases under "Known limits" are unmeasured.
**Date**: 2026-09-25
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: transport, quic, congestion-control, throughput, wireless

## Context

PRD-001 R41 says a Vox tunnel must not throttle the network it runs over. Throughput is to be as
high as possible without giving up any other goal or any security property.

Cubic reads every lost packet as congestion and cuts its rate. On a link that loses packets for other
reasons, such as Wi-Fi interference, the cut is wrong: the tunnel slows down on a network that still
has capacity. BBR fixes random loss, but it is much slower than Cubic on a clean LAN. No single controller
wins on every link, so Vox moves each connection between controllers as the path's signals change.

Prior art: TCP Westwood and TCP Veno, which tell random loss from congestion loss; Antelope (ICNP 2021;
IEEE/ACM ToN 2023), which switches algorithm mid-flow; Libra (2025).

## Requirements

### The goal: speed only (the decider, 2026-10-02)

- **SP-1 (goal 1, faster on a lossy link).** On each lossy arm, Vox MUST carry at least **2×** the
  comparison flow (TC-1) on the same loss.
- **SP-2 (goal 2, never slower).** Vox MUST NOT be slower than the controller it replaces on a clean,
  a congested or a changing link. On a clean link that means at least **90%** of raw TCP over the
  same link (the clean bar). On a congested link it means at least **0.5×** the comparison flow
  sharing the link.
- **SP-3 (goal 3, no stalls).** A switch between tiers MUST NOT stall a transfer (PR-4).
- **SP-4.** Fairness to other flows is a non-goal. ADR-024 MUST NOT claim a competing flow's rate,
  and R41 MUST NOT gate one. The decider withdrew these on 2026-10-02:
  - the lossy shared arm, where a Cubic flow beside Vox kept 90% of its solo rate;
  - the joined arm;
  - the 2× upper bound on a congested arm;
  - tier 2's hold at a small queue (`HOLD_DELAY_*`);
  - tier 3's exits on a queue, on a rising loss share, on an ECN mark and on persistent congestion.

  None of these is in the code.
- **SP-5.** Security and consent MUST be untouched (rule 6). The controller runs inside quinn and
  sees no plaintext, keys or identities. No change for speed MAY weaken crypto, the PQ handshake,
  consent or authentication.

### The comparison flow

- **TC-1.** R41 MUST compare against TCP's algorithm, not kernel TCP: a **quinn-Cubic flow**. That
  is a QUIC flow under quinn's stock `CubicConfig` (RFC 8312) with the tunnel's 8192-byte datagram
  ceiling and windows. It MUST cross the same emulated link and the same loss draw as Vox and, on
  congested arms, the same queue. (The decider, 2026-10-01: this counts as TCP for v0.2.10. Shaping
  kernel TCP needs root, and Vox's agents never run as root.) The speed claims are against RFC 8312
  Cubic, not against any kernel's TCP.
- **TC-2 (Planned, optional).** A race against real kernel TCP on Linux MAY be added later.

### The shape

- **C-1.** There MUST be one Vox controller, a custom quinn `ControllerFactory`, with three tiers.
  It MUST move one tier at a time, both ways. It MUST NOT change the QUIC stack (no move to noq), and
  it MUST NOT patch quinn.
- **C-2 (tier 1, Cubic).** Tier 1 is `VoxCubic`: quinn-proto 0.11.18's Cubic, ported unchanged
  except that HyStart++ ends slow start per RFC 9406 §4.2. Every connection MUST start in tier 1, and
  a clean link MUST NOT leave it.
- **C-3 (tier 2, loss-aware Cubic).** Tier 2 is `VoxCubic` with one change: a loss that `PathSignals`
  does not call congestion MUST cost **no** cut. A smaller cut is not enough (M24.1). A loss with a
  queue, a loss past the loss cap (SG-5) or past the loss trend (SG-6), a loss under persistent
  congestion, and an ECN mark MUST each cost Cubic's normal cut.
- **C-4 (tier 3, BBR).** Tier 3 is `VoxBbr`, a Vox-owned port of quinn-proto 0.11.18's BBR (the
  decider, 2026-10-01). It is owned by Vox so that a switch into it can be seeded with the current
  rate (TB-2). It MUST differ from quinn's BBR in two estimators:
  - its minimum round trip is BBR's own 10 s windowed minimum, not `RttEstimator::min`;
  - its bandwidth estimate is the BBR draft's delivery-rate sampling, with every sample fed to the
    10-round max filter.

  Every packet of a batched (GSO) send MUST give a rate sample. The gain cycle's random offset MUST
  be drawn with `getrandom`. Its window MUST be quinn's: twice the estimated bandwidth-delay product
  plus the measured acknowledgement aggregation (`K_DERIVED_HIGH_CWNDGAIN` 2.0, option A). Option C
  (one BDP, no aggregation allowance) was rejected for speed.
- **C-5 (rule 1).** A climb MUST be one tier at a time, and only on evidence sustained over many
  round trips. A single event MUST NOT cause one.
- **C-6 (rule 2).** A descent MUST also be one tier at a time (3 → 2 → 1), after a quiet stretch
  with no loss and no queue. The next step MUST be checked again before it is taken. A descent MUST
  NOT be judged on "throughput holding": a rate measured on the connection cannot tell a slower path
  from a quieter application or from an older, faster path.
- **C-7 (rule 3).** Tier 3 MUST be kept only while it is faster (TB-3), with a back-off before it
  may be entered again (TB-4).
- **C-8 (rule 4).** Each tier MUST have a minimum dwell, and the climb and descent thresholds MUST
  differ (hysteresis).
- **C-9 (rule 5).** A switch MUST NOT restart the connection's ramp. The current rate and window MUST
  be handed to the next tier, so a switch costs no slow start.
- **C-10.** Each tier switch MUST emit `tracing::debug!` under the target `vox::congestion`, giving
  the tiers, the reason and the signal that decided it. Nothing prints by default.

### Signals (`PathSignals`, M24.1)

All three tiers MUST read one helper, `PathSignals` in `congestion.rs`, fed from quinn's `Controller`
callbacks. A round ends when a packet sent after the round began is acknowledged. Each
acknowledgement's round-trip sample is its own `now - sent`. An application-limited round is no
evidence either way.

- **SG-1 (base round trip).** The base MUST be the lower of:
  - the minimum over the last `BASE_RTT_WINDOW` (10 s);
  - the minimum of the latest **small round**: one that acknowledged at least two packets and at most
    `SMALL_ROUND_BYTES` (32 KiB).

  The small round's value MUST be replaced at the next small round, not kept as a minimum. The base
  MUST NOT be quinn's lifetime `RttEstimator::min`.
- **SG-2 (a queue is building).** A queue MUST be read when the last finished round's **minimum**
  round trip exceeds the base by at least max(`QUEUE_DELAY_MIN` 4 ms, `QUEUE_DELAY_SHARE` 40% of the
  base). It MUST NOT use the smoothed round trip.
- **SG-3 (a round too small to time).** A round that acknowledged fewer than `TIMED_ROUND_PACKETS`
  (4) packets MUST give no round minimum and no queue.
- **SG-4 (loss share).** The loss share is lost bytes over lost plus acknowledged bytes.
- **SG-5 (loss cap).** Past `GENTLE_LOSS_CAP` (5%) of the bytes sent over the last `LOSS_ROUNDS`
  (8) rounds, every loss MUST be called congestion.
- **SG-6 (loss trend).** On entering tier 2, the loss share of tier 1's sending MUST be recorded as
  tier 2's baseline. The baseline follows the trend up, never down, until tier 2 has sent
  `TREND_BYTES` (32 MiB) of its own, and then holds. Once the share over the last 32 MiB sent passes
  max(`LOSS_RISE_FACTOR` 1.5 × baseline, baseline + `TIER2_LOSS_RISE` 0.5 points), every loss MUST be
  called congestion.

### Tier switches (`taper.rs`), evaluated once per round trip

- **TS-1 (dwell).** A connection MUST spend at least `DWELL_TIME` (2 s) and `DWELL_ROUNDS` (20
  rounds) in a tier before any switch.
- **TS-2 (1 → 2).** After tier 1's dwell, tier 1 MUST climb when all of these hold:
  - at least `CLIMB_1_LOSSES` (3) losses of either kind, with or without a queue, in the last
    `CLIMB_1_ROUNDS` (8) rounds;
  - in each of those 8 rounds, no queue had been held for `CLIMB_3_QUEUE_ROUNDS` (8) rounds in a
    row;
  - the loss share over the last 32 MiB is at least `TIER2_ENTRY_SHARE` (0.5%).
- **TS-3 (2 → 1).** After tier 2's dwell, tier 2 MUST descend after `QUIET_ROUNDS` (40) rounds and
  `QUIET_TIME` (4 s) with no loss and no queue in any of them. Tier 2's loss baseline MUST then be
  cleared.

### Tier 3 (`VoxBbr`, M24.4)

- **TB-1 (2 → 3).** After tier 2's dwell, tier 2 MUST climb when:
  - the loss share over the last 32 MiB is **at or above** `GENTLE_LOSS_CAP`;
  - that has held through at least `CLIMB_3_ROUNDS` (20) rounds and `CLIMB_3_TIME` (2 s);
  - in those rounds, no queue was held for `CLIMB_3_QUEUE_ROUNDS` (8) rounds in a row;
  - no tier-3 back-off is running.

  A link at exactly 5% is the boundary and MAY stay in tier 2 (the decider, 2026-10-01).
- **TB-2 (seed).** Tier 3 MUST start in ProbeBW, never in Startup. It MUST be seeded with:
  - tier 2's window over its smoothed round trip, as its rate;
  - the base round trip (`PathSignals::min_rtt`);
  - tier 2's window.

  It MUST NOT be seeded with a best rate kept from earlier, which can belong to another path.
- **TB-3 (the speed exit).** Vox's delivered rate over the last `RATE_WINDOW` (2 s) MUST be recorded
  at 2 → 3. Once tier 3 has dwelt, a round whose rate over the same window is under `TIER3_SLOWER`
  (0.9×) of that record MUST take the connection back to tier 2. The exit MUST be judged only when
  no application-limited round fell within the last 2 s.
- **TB-4 (back-off).** After a TB-3 exit, tier 3 MUST be locked out for `BACKOFF_FIRST` (30 s). The
  lockout doubles after each further exit, up to `BACKOFF_MAX` (8 min). It returns to 30 s only after
  a tier-3 stay of `BACKOFF_RESET` (5 min) with no exit.
- **TB-5 (3 → 2 when the loss goes).** After tier 3's dwell, tier 3 MUST descend when the loss
  share over the last 8 rounds stays under half the cap (2.5%) for `QUIET_ROUNDS` (40) and
  `QUIET_TIME` (4 s). No back-off follows this exit. TB-3 and TB-5 MUST be tier 3's only exits.
- **TB-6 (hand-down).** Both exits MUST hand down to a loss-aware `VoxCubic` seeded in congestion
  avoidance at BBR's delivery rate × the base round trip.
- **TB-7 (pacing).** quinn-proto 0.11 paces from the window and the smoothed round trip, and never
  reads a controller's pacing rate. So `VoxBbr`'s gains, its probing cycle included, act through its
  window alone.

### Idle restart

- **IR-1.** `IdleRestart` MUST start a fresh controller after the connection sends nothing for
  `IDLE_RESTART` (1 s) and `IDLE_RTTS` (4) round trips. The tier and the 10 s base round trip reset
  with it: the next transfer starts in tier 1.
- **IR-2.** The tier-3 lockout MUST survive an idle restart (`Tier3Backoff`).

### Receiver overflow (R41a, #218)

A receiver behind a short socket buffer that stops reading for a moment overflows its own socket,
and its sender's tier 1 read every such loss as congestion: with a 416 KiB buffer (a container on
a host that keeps Linux's default `net.core.rmem_max`) and the receiver stopped 20 ms in every
100 ms, R41's WAN arm carried 9–10% of raw. The path was never congested.

- **RO-1 (the count).** A receiver MUST read its endpoint socket's own drop count (Linux
  `SO_MEMINFO`, `SK_MEMINFO_DROPS`), every `SAMPLE_EVERY` (5 ms) while the socket is receiving and
  never while it is idle. The read MUST be the one `getsockopt` in `crates/vox-sockdrops`, the only
  Vox crate that allows `unsafe`. Where the kernel keeps no per-socket count (macOS), nothing MUST
  be read or sent, and nothing changes.
- **RO-2 (the wire).** The count MUST travel in a QUIC DATAGRAM on flow `3`, a unidirectional
  stream id that no flow can bind: `varint 3 ‖ varint 0 ‖ varint epoch ‖ varint drops`. `epoch` is
  drawn at random when the socket is bound; `drops` is the cumulative count. Any other kind on flow
  3 MUST be dropped and counted as an unknown flow.
- **RO-3 (who is told).** Each direct connection MUST send its peer the count when it has changed
  and the peer has sent on that connection since the last report. A connection over a relay
  circuit MUST NOT send one.
- **RO-4 (credit).** A report's increase over the last report of the same epoch, in packets, is
  credit, filed in the connection's `OverflowLedger`. Credit MUST expire one smoothed round trip
  after it arrives, never sooner than `CREDIT_FLOOR` (10 ms).
- **RO-5 (skip and undo).** A loss of packets in tier 1 or 2, not persistent congestion, with no
  queue building (SG-2), whose packets (lost bytes over the path MTU, rounded up) the credit covers
  MUST cost no cut. A cut whose loss the credit covers within one smoothed round trip of the cut
  MUST be undone: window, slow-start threshold, Cubic's curve and HyStart++'s phase restored to just
  before it, its recovery period kept, never to a window lower than the current one. Credit MUST be
  spent oldest first, all or nothing per loss. An ECN mark, persistent congestion, a loss with a
  queue building and any loss in tier 3 MUST NOT be covered.
- **RO-6 (signals).** A covered loss MUST be taken out of `PathSignals` (the loss share, the cap,
  the trend and the climb counts), so overflow neither climbs a tier nor holds one.
- **RO-7 (status).** `vox status --json` MUST give each peer's `overflow`: reports sent and
  received, unspent credit, cuts skipped and cuts undone.

Known limits: one socket serves every peer, so an overflow is reported to each active sender and
each may spend it on its own losses; a covered loss that coincided with congestion showing no queue
is forgiven. A receiver can claim overflow it did not have and so keep its sender from cutting
toward it; persistent congestion still cuts. Where receive offload (GRO) coalesces datagrams, one
drop counts one, so credit is short and Vox falls back toward cutting. Neither bound is measurable
by a speed arm (SP-4); both are review-checked.

### Proof (M24.2, R41)

- **PR-1.** Each arm MUST be driven through the shipped binary and judged by the speed a person
  sees, never by which tier is running (the decider, 2026-10-01). A red MUST name PRODUCT or
  APPARATUS. APPARATUS covers three faults: the emulator was late (PR-9), the tunnel's bytes did not
  cross the emulated link, or the comparison flow did not run. An APPARATUS fault ends only its own
  arm.
- **PR-2 (lossy).** At 200 Mbit/s, 10 ms, with 1% and with 6% random loss, Vox MUST carry at least
  `LOSSY_WIN` (2×) the comparison flow. The heavy arm runs at 6%, clearly past tier 2's 5% cap (the
  decider, 2026-10-01).
- **PR-3 (congested).** The link is shared with the comparison flow through one queue:
  - 200 Mbit/s, 10 ms, with a 1-BDP queue;
  - 200 Mbit/s, 10 ms, with a ¼-BDP queue;
  - 400 Mbit/s, 2 ms, with a 1-BDP queue (a full queue there is 2 ms, under SG-2's floor).

  Each is judged over `CONGESTED_MEASURE` (60 s), so that a tier-3 stay falls inside the run. Vox's
  rate MUST be at least `CONGESTED_FLOOR` (0.5×) the comparison flow's. There is no upper bound. The
  2 s windows are printed as DIAGNOSTIC only.
- **PR-4 (no stall).** On the lossy and the changing arms, no 2 s window of Vox's MUST fall under
  `STALL_FLOOR` (0.5×) of the comparison flow's mean rate on the same loss. It is judged from the
  first lossy second with no settle allowance.
- **PR-5 (changing).** Two changes run under one transfer: clean → 1% loss → clean, and clean → 6%
  loss → clean. Each phase lasts `PHASE` (30 s). Every 2 s window of each clean phase MUST be at the
  clean bar, and back at it within `RECOVER_WITHIN` (5 s) of the loss ending. The lossy phase MUST be
  at that loss's lossy bar. A red MUST name its phase (CLEAN, LOSSY or RECOVERY) and print the
  per-second series.
- **PR-6 (paused).** On the 1% and the 6% link, a transfer stops for `PAUSE` (3 s, longer than
  `IDLE_RESTART`) and resumes. It MUST be back at the lossy bar within 8 s at 1% and within 20 s at
  6%, and its mean after that MUST be at the bar.
- **PR-7 (tier 3 within 20 s).** On the 6% lossy, changing and paused arms, the first 2 s window at
  the lossy bar MUST end within `TIER3_WITHIN` (20 s) of the loss starting or the transfer resuming.
- **PR-8 (clean LAN-like).** At 400 Mbit/s, 2 ms, every one of 30 seconds MUST be at the clean bar.
  R41's 1 Gbit/s LAN link stays as it is.
- **PR-9 (CANNOT MEASURE).** An arm MUST be CANNOT MEASURE in either of two cases:
  - more than `LATE_SECONDS_SHARE` (10%) of its judged seconds had at least `LATE_PACKET_SHARE`
    (half) of their packets released at least `QUEUE_SIGNAL_LATENESS` (4 ms) late;
  - any second ran more than `MAX_EMULATOR_LATENESS` (25 ms) late.

  Every arm MUST print its per-second late share.
- **PR-10.** R41's watchdog budget is 1800 s.
- **PR-11 (M24.5 acceptance, the decider, 2026-10-02).**
  - LAN and WAN MUST stay at least 90% of raw.
  - Each lossy arm MUST be at least 2× the comparison flow.
  - Each congested arm MUST be at least 0.5× the comparison flow.
  - The changing arms MUST hold as PR-5 states.
  - No switch between tiers MAY stall a transfer.
  - Every proof MUST drive the shipped binary and be mutation-checked.
- **PR-13 (R41a).** On Linux, at 1 Gbit/s and 50 ms, with the receiving host granted 416 KiB
  (`VOX_TEST_UDP_RCVBUF_CAP`) and its daemon stopped 20 ms in every 100 ms, the tunnel MUST carry at
  least `STALLED_FLOOR` (50%) of raw TCP through the same stalls. It is CANNOT MEASURE off Linux,
  when the short buffer was not granted, when the kernel counted no receive overflow, or when the
  stopper or the emulator ran late.
- **PR-12 (opt-in).** R41 is a heavy proof. It is opt-in behind the cargo feature `optional-proofs`
  (#301) and listed in `docs/release/optional-proofs.md`. It MUST NOT be part of every build, CI run
  or release run (ADR-018). Without the feature, a stand-in MUST say it was not run.

### Known limits (no claim is made)

None of these is built or measured for this release (the decider, through vox, 2026-10-01). How the
design behaves on them is unknown.

- **L-1 Jittery links (cellular).** Delay that varies from round to round may read as a queue, which
  holds tier 2 at Cubic's behaviour. If it does not, the link's losses are treated as random.
- **L-2 Bursty loss.** A burst can push the loss share over the cap. Loss that averages at or above
  the cap with no held queue meets TB-1, so the link can enter tier 3. It leaves if tier 3 is slower
  there.
- **L-3 AQM (fq_codel, CoDel, CAKE).** Early drops at a short queue may read as random loss. Whether
  the loss trend catches them, and how flow queueing changes the outcome, is unmeasured.
- **L-4.** Two or more competing flows, and a shared 50 ms WAN link, are unmeasured.
- **L-5.** Every threshold rests on one or two runs per case, at one link rate and round trip per
  case.
- **L-6 (N1, a tier 3 judged against an old rate).** TB-3 compares tier 3 with tier 2's rate before
  the switch. If a lossy link's capacity falls while Vox is in tier 3, tier 3 can be slower than tier
  2 was and still faster than tier 2 would now be. Vox then drops to tier 2 and is locked out of tier
  3 for 30 s, doubling to 480 s. It is never slower than the controller it replaces, which has no
  tier 3.
- **L-7 (N3, datagram size).** Every threshold was measured with 8192-byte datagrams
  (`MAX_UDP_PAYLOAD`), at 200 Mbit/s with 10 ms and at 400 Mbit/s with 2 ms. A path limited to
  1200-byte datagrams is unmeasured. The thresholds that count packets or bytes
  (`TIMED_ROUND_PACKETS`, `CLIMB_3_QUEUE_ROUNDS`, `TREND_BYTES`) shift with datagram size.
- **L-8 (warm-up after the round trip grows).** For about 10 s after a path's round trip grows, the
  old base makes every loss read as congestion, and Vox runs at tier 1's rate. When the round trip
  shrinks, the base follows at once.
- **L-9 (the queue test is blind at a short full queue).** Where a full queue is shorter than SG-2's
  floor (2 ms of delay at 2 ms RTT), the loss signals are the only guard.
- **L-10 (rule 5 unproven for speed).** No arm is both lossy and long-RTT. The verifier's reset
  mutant (MUTANT-VER244-RESET) stayed green at 10 ms RTT, where BBR re-ramps within about a second.
- **L-11 (unproven guards).** These stay in the code, but no arm shows that they matter for speed:
  - SG-3: with the tier-2 hold gone, a mutant restoring the misread read 4.835× on the 6% arm (one
    run). It is kept because a false queue reading is wrong input to every tier (the lead,
    2026-10-02).
  - TB-3's application-limited guard: a mutant without it stayed green on the 6% paused arm.
  - SG-5 and SG-6: whether removing either would make Vox faster on a gated arm is unmeasured.
- **L-12 (congestion misread as random loss).** Loss differentiation can misread congestion as
  random loss, and Vox then takes a competing flow's share. This is accepted under SP-4. The likely
  cause, not traced: TS-2 counts losses with a queue, so a congested link's overflow losses take Vox
  up the tiers. A tier-3 stay on a congested path also takes competing flows' share
  for as long as it lasts.
- **L-13 (the comparison is softer than kernel TCP).** The comparison flow has no HyStart, no PRR and
  no RACK, and quinn paces from the window. A kernel TCP with RACK and PRR is likely to do somewhat
  better on a lossy link, so "2× the Cubic flow" is likely softer than "2× kernel TCP". This is
  unmeasured.
- **L-14 (calibration under load).** R41's 1 Gbit/s LAN link often cannot calibrate on a machine
  doing ordinary work, where each calibration window needs 95%. The clean LAN-like arm (PR-8) runs at 400 Mbit/s for this reason.

## Consequences

- Clean links keep Cubic's speed. Lossy links get BBR's gain only where it is faster.
- Vox stays on quinn 0.11, and quinn is not patched. Tier 1 and tier 3 are Vox's ports of quinn's own
  controllers. `tracing` is a direct dependency (default features off, `std`); quinn already brings
  it in.
- Vox maintains a controller of its own, with thresholds of its own.
- Vox can take more than a competing flow's share (L-12). This is accepted.
- If quinn later ships a BBR that holds a clean LAN, tier 3 MAY adopt it without changing the shape.

## Related ADRs

ADR-011 (transport substrate; its "Throughput (R41)" raises the flow-control windows, which this ADR
does not concern), ADR-018 (proof from the user's vantage; heavy proofs opt-in). PRD-001 R41.
Rejected alternatives: BBRv1 as the default, a move to noq for BBRv3, and the noq stack on its own.
Prior art:
- Antelope, <http://www.eecs.qmul.ac.uk/~tysong/files/ICNP21.pdf> and
  <https://dl.acm.org/doi/10.1109/TNET.2022.3220225>;
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
