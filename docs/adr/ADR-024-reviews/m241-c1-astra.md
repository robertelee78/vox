## 1. Queue detection: absence of this signal does not establish absence of congestion

The proposed threshold is strongly RTT-dependent but insensitive to bottleneck service rate, packet size, and queue-management policy. Applying ADR:124–125 literally:

| Path | Required RTT excess | Equivalent queue at bottleneck rate | Principal blind spot |
|---|---:|---:|---|
| 1 Gbit/s, 2 ms LAN | 4 ms | 500 KB, **2 BDP** | Even a full 1-BDP queue can remain below the threshold. |
| 50 ms WAN | 20 ms | 0.4 BDP; 2.5 MB at 1 Gbit/s | Early congestion signals at substantially less than 20 ms delay. |
| 20 Mbit/s, 60 ms cellular | 24 ms | 60 KB, 0.4 BDP | Congestion below 24 ms; conversely, correlated radio/ACK delay above it. |

These are arithmetic consequences of the proposed rule, not measured failures.

**False negatives have a dangerous consequence:** tier 2 ignores the congestion loss; tier 3 may remain eligible. **False positives have a performance consequence:** random loss receives normal Cubic reductions, or blocks/exits tier 3.

Three additional problems matter:

- **A round minimum detects sustained delay, not every congestive queue.** A burst can overflow a shallow buffer and then drain before a successfully acknowledged packet supplies the round minimum. Using the *previous* completed round also delays response to newly arriving cross traffic. Selecting the minimum is reasonable noise rejection, but “no queue” is too strong an interpretation.
- **The ten-second minimum can absorb a persistent queue.** Suppose the propagation RTT is 50 ms and a queue keeps every sample at or above 80 ms for ten seconds. The new base can become 80 ms; an unchanged congested path then shows approximately zero excess. The classifier has lost its reference. Expiry solves stale route history but creates this separate failure mode unless accompanied by baseline validation or drainage.
- **Raw send-to-ACK duration is not forward-path queue delay.** The callback exposes `now`, `sent`, and the RTT estimator, but no per-packet ACK-delay correction; callbacks are batched. Quinn updates the estimator with the ACK’s delay **after** the controller’s ACK callbacks and `on_end_acks`. Thus reverse-path congestion, delayed ACKs, and endpoint scheduling can contaminate the proposed samples. Taking a minimum helps only when some samples escape that contamination.  
  **Code:** `Q/congestion.rs:22–45`; `Q/connection/mod.rs:1530–1551,1616–1627`.

The unconditional claim that **every RTT increase causes ten seconds of congestion classification** is also false as a consequence of the stated formula: an increase below the threshold does not trigger it, and the old minimum expires according to its sample age, not necessarily ten seconds after the path change. **ADR:117–122,210–211.**

**Required correction:** treat insufficient or ambiguous queue evidence explicitly. The design needs a policy for stale/inflated baselines, sparse samples, reverse-path delay, and path changes—not merely different constants.

## 2. No-cut loss handling: the cap is not a fairness guarantee

### Policers and low-delay AQM are counterexamples to the inference

A policer can discard packets without building a queue. A dropping AQM intentionally signals before a large standing queue develops. For example, CoDel’s recommended target is **5 ms**, substantially below this design’s WAN/cellular thresholds of 20–24 ms. CoDel’s target is not a strict upper bound, but congestion drops can occur while Vox still classifies the path as “no queue.” See [RFC 8289 §4.3](https://www.rfc-editor.org/rfc/rfc8289.html#section-4.3).

If both flows encounter sub-cap congestion loss and only the Cubic competitor reduces its window, Vox can gain share **because the competitor yielded**, without Vox’s own loss percentage reaching 5%. Nothing in the cap establishes a lower bound on the competitor’s throughput.

Distinguish the queue disciplines:

- **FIFO with CoDel:** the flows share the queue; the above competition problem directly applies.
- **fq_codel:** separate flow queues and scheduling can protect the competitor. I would **not** claim starvation across independently scheduled queues merely because Vox ignores drops. That protection belongs to the scheduler, however; it does not validate Vox’s classifier. See [RFC 8290](https://www.rfc-editor.org/rfc/rfc8290.html).

Deep buffers initially make delay detection easier, but the persistent-queue baseline problem described above can erase that protection.

### Why “5% over eight rounds” is insufficient

The cap is a **response trigger**, not a hard loss ceiling or fairness constraint:

- It responds after loss has occurred.
- Eight rounds represent approximately 16 ms, 400 ms, or 480 ms on the three example paths, before queue inflation.
- Loss measurements arrive later than the corresponding transmissions. The ADR does not define whether numerator and denominator describe the same transmission cohort.
- Packet/sample counts vary with MTU, RTT, throughput, and application limitation.

For illustration, using the ADR’s approximate 15-packet window gives only 120 packets over eight rounds. Under an ideal independent 5% packet-loss model, the loss-fraction standard deviation is about **2 percentage points**. Adjacent rolling windows overlap, so repeated threshold observations are not independent evidence. This illustration is not an estimate of the actual spike’s confidence interval. **ADR:145–150.**

“Every loss” also needs precise terminology. Quinn delivers a congestion callback for a **batch** of lost packets, and Cubic suppresses additional reductions for packets sent before its recovery boundary. A cap should retain those semantics rather than accidentally reducing per lost packet or counting one batch as one packet.  
**Code:** `Q/connection/mod.rs:1768–1815`; `Q/congestion/cubic.rs:167–199`.

### Is congestion collapse demonstrated?

**No finding of demonstrated congestion collapse.** The supplied evidence does not establish it. Ignoring some losses is not equivalent to completely uncontrolled transmission: quinn still applies a congestion-window check. **Code:** `Q/connection/mod.rs:602–631`.

Nevertheless, the design does not establish safety against starvation-like unfairness, persistent overshoot, or wasted capacity across multiple bottlenecks. Its own uncapped shallow-buffer run is strong evidence of severe unfairness: **80.9 versus 15.4 Mbit/s**. The capped run is encouraging, but **40.0 versus 38.1 Mbit/s** for the competitor is far too small a difference, from separate single runs, to justify “keeps what it gets.” **ADR:154–161.**

Finally, the claim that **“any per-loss cut holds the rate”** overgeneralizes from one tested reduction factor, 0.85. An arbitrarily small cut has arbitrarily small effect; these two experiments do not prove zero reduction is uniquely necessary. **ADR:139–146.**

## 3. Tier 3: the trial does not identify random loss reliably or bound harm

### Flat loss share is not a causal discriminator

The ADR compares different controller runs and concludes that increasing rate separates random loss from congestion. **ADR:168–176.** That supports a hypothesis, not a reliable classification rule.

Counterexamples:

- **A competing flow leaves:** Vox’s delivery rate rises and congestion loss falls or stays flat. The trial can attribute released capacity to random loss.
- **A competing flow yields to Vox:** Vox gains bandwidth while aggregate offered load and loss remain similar. This is precisely an unfair result that a flat-loss test can accept.
- **A competing flow arrives:** additional congestion loss causes a failed trial, even when the pre-existing loss was genuinely random. Conservative rejection is defensible, but it shows the test does not identify the loss cause.
- **Bursty wireless loss:** the entry estimate may be inside or outside a burst. A later burst can falsely reject BBR; a quiet interval can falsely validate an unsafe trial.
- **A token-bucket policer:** its burst allowance can make a short probe appear safe before the sustained rate exceeds the policer’s allowance.

The experiment must distinguish **offered rate** from **delivered rate**. The table reports throughput; losses depend on offered traffic and the bottleneck’s state. The ADR does not define a controlled rate perturbation or require a minimum achieved perturbation.

### The proposed admission condition can exclude the intended case

Entry requires delivery below half the best of the previous ten seconds. **ADR:178–180.**

A connection that starts on a persistently 5%-loss path may never have demonstrated a much higher delivery rate. Once historical high-rate samples expire, current delivery may be close to the recent maximum despite remaining badly loss-limited. Tier 3 can therefore be unreachable on exactly the path it is meant to help.

Likewise, requiring a noisy estimate to remain at or above **its own 5% mean** for a sustained interval is not equivalent to identifying a 5%-loss link. The exact persistence/reset rule matters greatly.

### “At most two seconds of unfair share” is unsupported

The loss-growth rejection is restricted to the initial trial. After that, the stated exits are two rounds of queue evidence or loss below 2.5%. **ADR:181–187.**

Therefore a tier-3 flow can remain indefinitely on a congested path with:

- no detected queue; and
- loss above 2.5%, including loss that increases **after** trial completion.

Even during the trial, entry at 5% permits loss to rise to **8%** without exceeding the rejection threshold. A competitor may suffer severely before that threshold is crossed.

Other missing details:

- Does “20 rounds **and** 2 s” mean a two-second hard deadline, or waiting for both? Twenty rounds exceed two seconds when RTT exceeds 100 ms.
- What constitutes **successful** trial completion? Flat loss without improved useful delivery is not success.
- What window, recovery state, and growth epoch does failed-trial rollback use? Merely relabelling an enlarged window as Cubic does not promptly undo the excursion.
- A back-off that reaches eight minutes conflicts with “reset after five minutes without [a failed trial]” unless the reset excludes enforced back-off. A literal implementation can reset before the eight-minute retry.

**Required correction:** a bounded probe, explicit success/inconclusive/failure outcomes, specified rollback, and continuing safety evaluation after admission. Back-off alone cannot repair a trial that incorrectly passes.

## 4. Fairness: QUIC/Cubic is a useful control, not kernel TCP equivalence

The comparison improves on a TCP proxy that hides the emulated losses from TCP. It is useful for asking:

> Does the proposed controller outperform stock quinn Cubic under this apparatus?

It does not establish the broader claim “fair against TCP.” **ADR:109–115.**

Concrete differences:

| Mechanism | Relevant difference |
|---|---|
| **HyStart** | Stock quinn starts with effectively unlimited `ssthresh` and grows until loss; Vox adds HyStart++ delay-based exit. Linux v6.12 Cubic also has HyStart, but its ACK-train/delay implementation is not identical to Vox’s HyStart++. This can change startup overshoot, drops, and later history. |
| **PRR** | Kernel TCP can regulate recovery transmissions through Proportional Rate Reduction. Stock quinn Cubic’s window reduction and recovery-boundary handling do not establish equivalent recovery sending behavior. |
| **RACK** | Selective ACK information is not itself a loss-recovery algorithm. Linux RACK has reordering-window logic; quinn’s inspected loss detector uses its packet/time thresholds. Bursty loss and reordering can therefore produce different loss declarations and recovery. |
| **Pacing** | Quinn uses a userspace token bucket with refill derived from `1.25 × cwnd/SRTT`, and a capacity calculation clamped to 10–256 MTUs. Kernel pacing configuration and packet release behavior are separate variables. |

**Code references:**

- HyStart: `Q/congestion/cubic.rs:75–85,111–114`; `V:263–307,336–344`; [Linux `tcp_cubic.c:39–58,386–445`](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_cubic.c#L386-L445).
- Recovery: `Q/congestion/cubic.rs:102–108,167–214`; [Linux `tcp_input.c:2704–2727`](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_input.c#L2704-L2727).
- Loss detection: `Q/connection/mod.rs:1695–1735`; [Linux `tcp_recovery.c:5–35`](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_recovery.c#L5-L35).
- Pacing: `Q/connection/pacing.rs:87–112,129–151`; [Linux `tcp_input.c:937–968`](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_input.c#L937-L968).

Packetization is especially important here. The improvement is explicitly tied to 8192-byte datagrams, but **8192 is a conditional discovery ceiling**, not a universal operating MTU. The endpoint can select a 1452-byte ceiling, and transport configuration sets the MTU-discovery upper bound. **Code:** `crates/vox-core/src/transport/quic.rs:233–245,264–274`.

The document needs both a precisely named surrogate and evidence at ordinary path MTUs. Claims about macOS/Linux defaults also need OS/version/configuration qualification.

## 5. Source discrepancies and incomplete implementation contract

### A. Rate-seeded BBR is not yet a specified sending mechanism

The claim that `BbrConfig` cannot seed the bandwidth/rate model is correct: its public tuning method sets only the initial window. **No finding on that narrow claim.**  
**Code:** `Q/congestion/bbr/mod.rs:515–542`.

But porting BBR and assigning its `pacing_rate` does not make quinn send at that rate:

- BBR computes the rate and exposes it through metrics.
- The actual send path passes **SRTT and `window()`** to the pacer.
- The pacer refills from cwnd/SRTT.

**Code:** `Q/congestion/bbr/mod.rs:284–306,494–499`; `Q/connection/mod.rs:623–631`; `Q/connection/pacing.rs:87–112`.

This is a material omission in ADR:86,98–99. The design must say how the port affects actual sending, and distinguish preserving a bandwidth estimate from preserving an immediately realizable sending rate.

### B. A literal BBR port inherits problems relevant to this design

1. **RTT expiry:** BBR refreshes its minimum from `rtt.min()`, not the proposed ten-second `PathSignals` minimum. Its ten-second ProbeRTT scheduling does not by itself fix that source.  
   **Code:** `Q/congestion/bbr/mod.rs:213–218,400–413`.

2. **Bandwidth decline:** the bandwidth estimator calls its maximum filter only when a new sample exceeds the current estimate. Lower samples therefore do not advance expiry through that path; `end_acks` only updates byte accounting. This matters when capacity falls or a competitor arrives.  
   **Code:** `Q/congestion/bbr/bw_estimation.rs:64–80`; filter ageing is inside `Q/congestion/bbr/min_max.rs:51–106`.

3. **ECN and persistent congestion:** stock BBR’s congestion callback ignores the persistent-congestion flag and only accumulates lost bytes. ECN callbacks carry zero lost bytes, so an isolated ECN event receives no distinct response there.  
   **Code:** `Q/congestion.rs:48–60`; `Q/congestion/bbr/mod.rs:468–476,623–630`.

These are not proof that the future `VoxBbr` will have those defects. They are changes that the port specification must explicitly address.

### C. “Exact signals” remain underspecified

The controller API exposes batched sends, per-packet ACK callbacks without packet numbers, batch-end largest ACK numbers, and aggregated loss callbacks. **Code:** `Q/congestion.rs:18–60`.

M24.1 still needs to define:

- delivery-rate estimator, interval, units, and application-limited handling;
- packet loss versus loss-event counting for “three losses”;
- aligned sent/lost accounting and loss attributed across round boundaries;
- round boundary convention and stale/no-sample behavior;
- Cubic window, `ssthresh`, `W_max`, epoch, and recovery handoff;
- precedence between the one-second entry condition and two-second dwell;
- whether descent requires “no loss and throughput holding,” or merely no **no-queue** loss.

The last two are actual textual inconsistencies. **ADR:91–99,178–192.**

### D. Factual and tense corrections

- **“quinn’s Cubic, unchanged” is stale.** The configured controller is `IdleRestart` around `VoxCubic`; idle restart reconstructs it, and slow start incorporates HyStart++.  
  **ADR:21,84; code:** `V:56–64,75–85,336–344`.
- **No finding in the copied congestion-avoidance equations or ordinary multiplicative decrease.** The inspected Vox and local quinn implementations agree there.  
  **Code:** `V:197–214,345–369,403–418`; `Q/congestion/cubic.rs:35–56,131–163,182–213`.
- **“Lifetime minimum” is substantially correct but should mean the estimator’s lifetime.** Samples are not time-expired, but path reset reconstructs the estimator.  
  **ADR:117–119; code:** `Q/connection/paths.rs:139–147,325–352`.
- **The prior-art “do not back off” statement is false.** Veno reduces to 4/5 in the non-congestive state. Westwood+ sets window/threshold from estimated BDP; neither supports blanket loss suppression.  
  **ADR:68–70; code:** [Linux `tcp_veno.c:200–205`](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_veno.c#L200-L205), [Linux `tcp_westwood.c:217–222,240–253`](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_westwood.c#L240-L253).
- **Planned work written as done:** `PathSignals` “All three tiers read…” at ADR:105 should be prospective; the inspected factory/state still instantiate the existing Cubic implementation (`V:56–64,228–240`). M24.2’s arms “prove them” at ADR:208–209 is premature. “Reviewed by” all four models at ADR:220–222 needs completed, candidate-bound review evidence; the candidate’s issue comment says those reviews were starting. The top-level **“Not built”** correctly states implementation status.

## 6. Statistics: separate compelling observations from unsupported guarantees

### Large effects support the direction of investigation

The reported effects are sufficiently large to take seriously:

- Tier 2 no-cut versus tier 1 at 1% loss: **169.8 versus 57.3 Mbit/s**.
- BBR versus capped tier 2 at 5% loss: **176.6 versus 32.0 Mbit/s**.
- Uncapped tier 2 and BBR’s severe shallow-buffer unfairness.

**ADR:139–143,154–171.**

These establish compelling observations on the tested apparatus. They do **not** establish stable exact ratios, success probabilities, or transferability to other links.

### These conclusions need targeted repetition or new evidence

1. **Cap fairness:** 40.0 versus 38.1 Mbit/s is only about 5% apart. Repeat with independent seeds, flow-start orders, and time-resolved competitor throughput.
2. **Threshold quality:** the two RTT distributions already overlap. The 12% false-positive figure needs counts, run-to-run variability, and a measured false-negative rate.
3. **Trial discrimination:** 5.07% versus 5.03% does not prove invariance, and separate steady-state runs do not validate a two-second within-flow trial.
4. **Actual tier-3 reachability and rollback:** the data demonstrate standalone controller behavior, not the admission conditions, state handoff, deadline, or retry policy.
5. **Changing-arm recovery:** phase means cannot prove the proposed **every-second** requirement or worst-case recovery time. The reported changing run also exercises 1% loss, where the ADR says tier 2 suffices. **ADR:194–196,230–232.**

The apparatus supplies specific smoke: typical lateness of **2–6 ms**, maximum **18 ms**, versus a **4 ms** classification floor and **2.5 ms** shallow-buffer delay. Equal treatment of both flows does not remove controller-specific sensitivity to bursts and scheduling. **ADR:50–52,124–135,156–158.**

Similarly, the historical repeated BBR LAN failure supports a reproducible problem with that implementation/apparatus combination. It does not prove BBR intrinsically fails on clean LANs, or conclusively eliminate every emulator interaction. **ADR:43–46,93–95.**

Preserve build identities, seeds, run durations, loss placement/definition, actual MTUs, and time series. Repeat the uncertain claims and observed timing-sensitive cases; there is no reason to repeat every unrelated green.

---

**Tracking:** review recorded on [#154](https://github.com/robertelee78/vox/issues/154#issuecomment-5939715397), work key `robertelee78/vox:ADR-024:M24.1`. Phase retained as **Executing**, health **At risk**; Project reconciliation returned `verified: true`. The worktree remains clean.

## VERDICT

**REVISE**

1. Define conservative behavior for ambiguous queue evidence, inflated/stale baselines, jitter, and insufficient samples; validate the classifier beyond 200 Mbit/s/10 ms.
2. Replace the claim that the 5% cap proves safety with an explicit bounded congestion response and evidence covering policers, dropping AQM, deep queues, realistic MTUs, and competing-flow variations.
3. Specify trial reachability, an achieved probe, success criteria, a hard deadline, rollback state, continuing post-trial safety, and unambiguous back-off/reset semantics.
4. Specify actual BBR pacing integration and intentional changes to RTT filtering, bandwidth ageing, ECN, persistent-congestion handling, and state handoff.
5. Name the comparison QUIC/Cubic; either supply a pinned kernel-TCP comparison or narrow the fairness claims accordingly.
6. Complete the callback-level signal definitions and resolve contradictory transition rules; correct the code descriptions, prior-art claims, and premature completion wording.
7. Repeat the uncertain fairness/threshold/trial claims with independent runs and time-series evidence; retain the large single-run effects as motivation rather than acceptance guarantees.
