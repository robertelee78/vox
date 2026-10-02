## 1. The queue test (`max(4 ms, 40% of base)` over the 10 s windowed min) at other links

The threshold is calibrated entirely from one link: 200 Mbit/s, 10 ms RTT (ADR:124-135).

**1 Gbit/s LAN, 2 ms RTT — blind.** Threshold = max(4 ms, 0.8 ms) = 4 ms. BDP = 250 KB, so a *completely full* 1-BDP drop-tail queue adds 2 ms of delay. Even a 2-BDP buffer barely reaches the floor. At this RTT the queue test cannot see any realistic queue, so every congestion drop reads as "loss without a queue." The tier-2 entry gate (ADR:190, "≥3 losses without a queue in 8 rounds") then fires on pure congestion loss, and tier 2 applies no cut. The only remaining guard is the 5%/8-round cap — which lands at an equilibrium of cwnd ≈ (BDP+Q)/0.95, i.e. the queue held permanently full and ~5% of bytes dropped, until the cap trips. The cap's only evidence is one run at 10 ms RTT (ADR:152-158); nothing at 2 ms. The doc never states this blindness: the "40% of the base" term means the test is only as good as the RTT is long.

**50 ms WAN — partially blind.** Threshold = max(4, 20) = 20 ms. Any queue under 0.4 BDP (20 ms of standing delay) is invisible. A 0.3-BDP buffer (15 ms of added delay — large in user terms) reads as "no queue," losses read as random, no cut until the cap. The doc's Negative section (ADR:206-211) does not list "tier 2 may hold up to ~40% RTT inflation indefinitely on paths whose queues sit under the threshold" as a consequence; it should.

**20 Mbit/s cellular, 60 ms + jitter — false positives, safe direction.** Threshold = 24 ms. Cellular jitter events (scheduling, HARQ) routinely inflate *every* sample of a round for several consecutive rounds, which defeats the round-minimum robustness (the min only protects against isolated delayed ACKs — ADR:125-126). Random losses coinciding with a jitter event read as congestion → tier 2 cuts like Cubic. Consequence: the mechanism fails exactly on the high-jitter wireless paths it exists to help, collapsing back to tier-1 throughput. This is the safe direction (no unfairness, no collapse), but the doc's own noise table (ADR:128-131) shows a 12% misclassification rate even on its tame measured link; on cellular it will be far higher, and it is unmeasured.

**Base-window asymmetry.** The doc documents the RTT-grows direction (ADR:120-122, 210-211: 10 s of every loss reading as congestion). It does not document the reverse: when RTT *shrinks* (Wi-Fi→Ethernet handoff, route change — a tunnel's connection outlives its path, which is the doc's own premise at ADR:119-120), the base stays high for up to 10 s, the threshold stays at 1.4× the *old* base, and a full queue on the new path reads as no-queue. Bounded by the cap, but unacknowledged.

**Instrument contamination of the calibration.** The threshold sits in the gap between the noise p90 (4.3 ms) and the congestion p10 (4.7 ms) — a 0.4 ms margin (ADR:128-131) — measured in one run on an emulator that "ran at most 18 ms late, typically 2–6 ms" (ADR:51-52). The margin is *inside the instrument's own typical lateness band*. The repo's own proof treats emulator lateness as CANNOT MEASURE (`perf_r41_tunnel_throughput_proof.rs:26-29`); M24.1's calibration absorbs it as if it were link noise. The 4 ms/40% numbers need re-measurement at higher emulator fidelity before they can be called settled.

## 2. "No cut at all on a no-queue loss" — collapse, starvation, the cap

**Congestion collapse proper: no finding.** The no-cut phase is bounded by the 5%-of-bytes-over-8-rounds cap, so wasted link capacity is pinned near 5%; Jacobson-style collapse does not follow from this design.

**Starvation is the real risk, and it is under-evidenced.** Three untested path classes, all of which produce *loss with little or no queue* — exactly the tier-2 trigger:

- **Policers** (token-bucket, no queue at all): drop share = 1 − R_police/R. Tier 2 enters, doesn't cut, rate climbs until drop share hits 5% (R ≈ 1.05×R_police), cap trips, tier 2 becomes Cubic. Steady state is bounded — *if* the cap holds. Untested.
- **AQM (CoDel/fq_codel)**: CoDel drops at 5 ms sojourn — above the 4 ms threshold at 10 ms RTT, *below* it at ≥25 ms RTT (threshold 10 ms at 25 ms base). On WAN paths, AQM drops are invisible to the queue test, read as random, no cut until the cap. fq_codel's per-flow isolation helps the queue test see Vox's own queue, but only when it exceeds the threshold. Untested.
- **Multiple competitors**: the cap is measured against exactly one Cubic flow (ADR:150-158). With N competitors, Vox's *own* byte-loss share can stay under 5% while its share of the queue climbs — the cap is a per-sender byte ratio and does not bound Vox's share of the link. M24.2's congested arms (ADR:228-229) also specify one Cubic flow only, so this will not be caught at the gate either.

**Is the 5%/8-round cap sufficient?** At the one measured point (¼ BDP, 200 Mbit/s, 10 ms, one competitor, one run): 5.26× unfair without it, 1.35× with it, tail drops 44,101 → 2,338 (ADR:157-158). That is a big, believable effect. But 5% is a tuned number resting on that single run — the doc never says why 5% rather than 3% or 10%, and the 8-round window is 16 ms at LAN RTT (noise-dominated) vs 80 ms at the measured link. The doc's own claim "the guards are … the 5% loss cap (measured on a shallow buffer, above)" (ADR:207-208) generalizes from one run at one point. One run at one point is not a guard; it is an encouraging observation. Also unhandled: what "past the cap" latches — the doc says "every loss is congestion" (ADR:149) but never states when that latches *off* (hysteresis is promised generally at ADR:96-97 but not specified for the cap).

**Deep buffers**: fine — queue delay of tens of ms is above any threshold, tier 2 cuts normally. No finding.

## 3. Tier 3's trial

**The discriminator is taxonomically sound** and the measured separation is wide (5.07%→5.03% flat vs 4.3%→15.7% climbing, ADR:166-171). At the tested point it works. The problems are at the edges:

**(a) No post-trial loss-based exit.** After the first 20 rounds / 2 s (ADR:181-182), the *only* exits from tier 3 are the queue test (rule 3, ADR:185) and loss falling below 2.5% for 40 rounds / 4 s (ADR:186). A path whose congestion loss climbs with rate but stays under the fail threshold — entry share 5%, fail line max(7.5%, 8%) (ADR:182); a mildly oversubscribed link or a slow policer that lands at 6-7% — keeps BBR **indefinitely**. The trial proves the discriminator at entry and then never asks again. A standing ceiling (e.g., loss share above the entry share for N rounds post-trial → tier 2) is missing.

**(b) The back-off defeats itself.** "30 s, doubled after each failed trial up to 8 min, reset after 5 min without one" (ADR:182-184). Any back-off ≥ 5 min produces a gap longer than the reset window, so the back-off resets before it is ever served: 8 min is unreachable as a stable state; the effective ceiling is 4 min. As written, "up to 8 min" is dead. Consequence is bounded (a competitor pays ≤2 s of unfair share per trial, ~0.6% duty), but the text does not do what it says.

**(c) Competitor arrival/departure mid-trial.** Arrival during the trial → loss climbs → trial fails → correct outcome, 2 s cost. Departure during the trial → trial passes onto a now-quiet link; bounded by the 2.5%/40-round exit. Both acceptable. The nastier case is a *token-bucket policer with burst capacity*: the trial's 2 s can pass inside the burst allowance with flat loss, then the policer clamps — and per (a), nothing loss-based ejects tier 3 afterwards. quinn's BBR does have a recovery window (`bbr/mod.rs:336-362`, `window()` returning `min(cwnd, recovery_window)` at `bbr/mod.rs:464-472`), so it won't run away, but it will sit at the policed rate with standing loss — exactly what the taper was built to avoid.

**(d) Bursty random loss.** All loss arms are uniform random. Entry requires loss share ≥ cap *sustained* for 20 rounds and 2 s (ADR:178-180); a bursty-loss link (Wi-Fi interference bursts) with a low duty cycle never satisfies the continuity requirement and stays in capped tier 2 — the 2× goal fails on bursty links. Safe direction, but unmeasured and undiscussed.

**(e) Under-specification that matters for the "2 s of unfair share" bound (ADR:184):** which BBR mode VoxBbr enters at trial start. quinn's `Bbr::new` starts in Startup with pacing gain 2.885 (`bbr/mod.rs:72`, `K_DEFAULT_HIGH_GAIN`). Entering Startup on a congested link would blow the 2 s bound; the doc says the port is "seeded with the current rate" (ADR:86) but never says the port enters ProbeBw rather than Startup.

**Related fact about quinn-proto 0.11.18 the doc should state (omission, not error):** quinn never transmits at a controller's `pacing_rate`. The pacer is driven by congestion window and smoothed RTT (`connection/mod.rs:625-630`), refilling at 1.25×window/RTT (`connection/pacing.rs:92-95`); `pacing_rate` flows only to metrics (`bbr/mod.rs:494-498`; `connection/paths.rs:204, 233`). So in stock quinn, BBR's ProbeBw gain cycle (`K_PACING_GAIN = [1.25, 0.75, 1.0, …]`, `bbr/mod.rs:642`) modulates a number nothing reads. For the VoxBbr port this is load-bearing: "seeded with the current rate" (ADR:86) can only act through cwnd, and the gain cycle must be re-plumbed through cwnd or the port inherits a dead control channel. "quinn itself is not patched" (ADR:86) makes this the port's problem to solve, and the doc doesn't mention it.

## 4. The comparison flow: quinn stock Cubic vs kernel TCP

Verified differences, with citations:

- **No HyStart in quinn's Cubic**: slow start ends only via `on_congestion_event` (`congestion/cubic.rs:103-148`; there is no delay-based exit anywhere in the file). Linux TCP Cubic ships HyStart. Consequence: the comparison flow overshoots more in slow start than kernel TCP — irrelevant for the steady-state gated arms, relevant for the changing arm's ramps.
- **No PRR (RFC 6937)**: quinn's Cubic cuts once per event and blocks re-cuts while in recovery (`cubic.rs:167-172`). Kernel TCP's PRR keeps the pipe fuller during recovery. At 5% loss the comparison flow (23.0–25.1 Mbit/s, ADR:60) likely **understates** kernel TCP, so Vox's 7.68× on that arm (ADR:169) is flattered by an unknown amount. The 2× bar at 5% is against a soft target.
- **Loss detection**: quinn uses RFC 9002 packet-threshold 3 / time-threshold 9/8 (`connection/mod.rs:1700-1728`; defaults at `config/transport.rs:381-382`). Kernel TCP's RACK detects tail losses roughly an RTT sooner. Minor for bulk steady state.
- **Pacing**: quinn always paces via its token bucket (`connection/pacing.rs`; used at `connection/mod.rs:625`); kernel TCP paces only under fq. A paced comparison flow bursts less into shared queues — mildly gentler competition on the congested arms.

Net: as a *controller-vs-controller* race with identical packet size, identical loss, identical queue (ADR:109-115), quinn-Cubic is a defensible — arguably better — stand-in than kernel TCP, and the doc argues this correctly. But the acceptance multiples were calibrated against it, and the 5%-loss arm is flattered by the absence of PRR.

**One false claim of fact**: "(RFC 8312, the default of macOS and Linux TCP)" (ADR:112). True for Linux. For macOS this is unsupported and, on public knowledge of Apple's TCP stack (NewReno-family default; LEDBAT for background), false. I cannot verify this from code on this machine; flagging it as a claim that needs a citation or deletion, not as a verified error.

## 5. False statements about the code / planned work written as done

Verified **true** first, so they don't get re-litigated:

- `RttEstimator::min` is the connection lifetime minimum (field comment `connection/paths.rs:298`; updated only via `cmp::min` at `paths.rs:338`) — ADR:117-118 ✓
- `BbrConfig` cannot seed a rate: it holds only `initial_window` (`bbr/mod.rs:517-518`), and `Bbr::new` takes no `now` and starts in Startup (`bbr/mod.rs:65, 72`) — ADR:86 ✓
- quinn's Cubic leaves slow start only on loss (`cubic.rs:103-148`) — `congestion.rs:31-33` ✓
- "quinn paces" — `connection/pacing.rs`, wired at `connection/mod.rs:625` — `congestion.rs:226` ✓ (the pacer's burst capacity can reach 256 MTU, `pacing.rs:148-151`, so "burst limit L is unlimited" is loose but defensible)
- ECN marks do trigger `on_congestion_event` with `lost_bytes = 0` (`connection/mod.rs:1609`, via `process_ecn` at `:1588` and `detect_ecn` at `spaces.rs:175-205`) — ADR:85's ECN clause is real
- VoxCubic is a faithful port: `BETA_CUBIC`/`C`/`INITIAL_WINDOW` (`congestion.rs:160-164`) match `cubic.rs:12-14` and the default clamp (`cubic.rs:266` = 12,000); `on_congestion_event` (`congestion.rs:387-420`) matches `cubic.rs:167-216` including RFC 9438 fast convergence and the persistent-congestion collapse; HyStart++ constants match RFC 9406 §4.3 (`congestion.rs:168-178`)
- Tier 1 is wired in: `quic.rs:285` installs `IdleRestartConfig`; MTU ceiling 8192 (`quic.rs:174-176`) matches "Vox sends 8192-byte datagrams" (ADR:52)

**False or rule-violating:**

1. **ADR:105 — "All three tiers read one helper, `PathSignals` in `vox-core/src/transport/congestion.rs`."** No such item exists anywhere in the repository (grep confirms the names `PathSignals`, `BASE_RTT_WINDOW`, `QUEUE_DELAY_MIN`, `QUEUE_DELAY_SHARE`, `GENTLE_LOSS_CAP`, `LOSS_ROUNDS`, `VoxBbr` occur only in the ADR). Tiers 2 and 3 do not exist; and the claim is false even for the tier that does exist — `VoxCubic` reads `rtt: &RttEstimator` directly (`congestion.rs:320-327`). Present-tense location-and-behavior claim for unbuilt code, against the house rule ("write 'is to' or 'must' until it has landed").
2. **ADR:109-115 — "R41's comparison flow is TCP's algorithm on the same link: a QUIC flow under quinn's stock Cubic."** The committed proof still races raw TCP across a TCP shaper (`perf_r41_tunnel_throughput_proof.rs:10-16`, `:24`, `:109-110`, `:434`, `:627-630`, `:782`). The QUIC-Cubic comparison exists only in the uncommitted M24.1 spike. The sentence describes planned work as done; it should say the comparison flow *is to be* this, with the change landing in M24.2.
3. **ADR:84 — tier table: "1 — Cubic | quinn's Cubic, unchanged."** False as shipped and internally inconsistent with ADR:52: tier 1 is `VoxCubic` (ported Cubic + HyStart++) inside `IdleRestart` (`congestion.rs:228`, `:75-86`), which is measurably not "quinn's Cubic, unchanged" — the doc's own context section attributes the WAN fix and the idle-restart fix to exactly those changes.
4. **ADR:146 — "Cubic regrows about a quarter of a packet per round trip."** The implemented `w_est` slope is 3(1−β)/(1+β) ≈ 0.53 packets/RTT (`congestion.rs:208-214`; same formula at `cubic.rs:58-66`), and immediately after a cut `w_cubic`'s concave slope is steeper still. Off by ≥2×. Immaterial to the conclusion (the 0.85-cut experiment at ADR:142 measures it), but the number is wrong.
5. **Naming**: "quinn 0.11.18's Cubic" (ADR:52) / "quinn 0.11.18's BBR" (ADR:86) — 0.11.18 is *quinn-proto*'s version; quinn is 0.11.9 (`Cargo.lock:1639-1641` vs `:1659-1661`). ADR:221 gets it right.
6. **ADR:220-221** — "Reviewed by gpt-6-astra, glm-5.3, kimi-k3 and codex": process claim; I cannot verify it. No finding on truth, but note this review is happening under M24.1, whose milestone text says the review already happened.

## 6. Statistics: single-run vs robust

**Robust (effects large enough that one run each suffices as direction):** no-cut vs 0.85-cut (2.77× vs 1.01×, ADR:143); cap vs no cap at ¼ BDP (1.35× vs 5.26×, tail drops 2,338 vs 44,101, ADR:157-158); BBR at 5% loss (7.68×, ADR:169); BBR unfair when congested (7.22×, ADR:171); the 2026-09-25 LAN collapse of quinn BBR (6 runs, ADR:44-46).

**Single-run and load-bearing — must be repeated before thresholds are trusted:**
- The queue-threshold calibration itself: p90 noise 4.3 ms vs p10 congestion 4.7 ms, one run each side, on an emulator typically 2–6 ms late (ADR:51, :128-135). The margin is inside instrument noise. This is the weakest measurement in the document and it underpins the primary signal.
- The claimed 12% false-congestion rate (ADR:133) — one run's tail.
- "The Cubic flow keeps what it gets against another Cubic (40.0 against 38.1)" (ADR:160) — a 5% gap from one run; this is the fairness keystone for the cap and it has no error bars.
- The cap's exact value (5%) and window (8 rounds) — tuned at one point, never varied.
- The changing arm (ADR:194-196) — one transfer; "back at full rate within a second" rests on it.
- Tier-2-with-cap at 5% loss (32.0 Mbit/s, ADR:168) — one run; the tier-3 trigger's entry conditions are calibrated against it.
- **Everything tier-2/tier-3 is measured only at 200 Mbit/s, 10 ms RTT.** The 1 Gbit/s LAN and 50 ms WAN arms exist only for tier 1 (ADR:30-35, 2026-09-25). Nothing in M24.1 measures the queue test, the cap, or the trial at any other RTT — which is where every finding in §1-3 above lives.

## VERDICT

**BLOCK**

Required changes:

1. Fix the three present-tense falsehoods about code: ADR:105 (`PathSignals` — write "is to be read by all three tiers"; it does not exist), ADR:109-115 (the R41 comparison flow "is to be" QUIC-Cubic; the committed proof races raw TCP, `perf_r41_tunnel_throughput_proof.rs:10-16`), ADR:84 (tier 1 is not "quinn's Cubic, unchanged" — it is VoxCubic + IdleRestart, `quic.rs:285`).
2. Correct ADR:146's regrowth figure (≈0.53 packets/RTT from `w_est`, faster in the concave region), fix the quinn/quinn-proto version naming (ADR:52, :86), and either cite or delete the macOS-Cubic claim (ADR:112).
3. State the queue test's blindness explicitly: the test cannot see any queue shorter than max(4 ms, 40% of base) of standing delay — which at LAN RTTs is *all* realistic queues (a full 1-BDP queue at 1 Gbit/s, 2 ms is 2 ms of delay). Add the consequence (tier 2 relies solely on the loss cap there) and the RTT-shrink base-window direction to Consequences.
4. Add a post-trial loss-based exit from tier 3 (§3a: today only queue and loss-<2.5% exits exist; a mildly rate-responsive congested path at 6-7% loss holds BBR forever).
5. Fix the back-off reset inconsistency (§3b: with a 5-min reset, the 8-min cap is unreachable; either the reset counts only failed-trial-free time *after* a successful trial, or the cap must be < 5 min).
6. Specify which mode VoxBbr enters at trial start (Startup with 2.885× gain on a congested link breaks the "2 s of unfair share" bound), and state the quinn-proto 0.11.18 fact that `pacing_rate` is metrics-only (`connection/mod.rs:625-630`, `paths.rs:204,233`) so the port plans its ProbeBw gain cycling through cwnd.
7. Repeat the queue-threshold calibration at higher emulator fidelity before treating 4 ms/40% as measured: the current margin (0.4 ms) sits inside the instrument's typical lateness (2-6 ms, ADR:51). Repeat the cap's fairness keystone run (40.0 vs 38.1, ADR:160) and state why the cap is 5% over 8 rounds rather than neighboring values.
8. Add to M24.2 (or name as known-unproven): a congested arm at LAN RTT (1 Gbit/s, 2 ms) where the queue test is blind, at least one AQM or policer arm, and a two-competitor arm — the three cases where the 5% cap is the only guard and has no evidence.
