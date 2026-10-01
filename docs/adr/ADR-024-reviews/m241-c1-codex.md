ADR-024 is Accepted as a decision dated 2026-09-25, updated in prose on 2026-10-01, but explicitly “Not built” ([ADR-024:3](docs/adr/ADR-024-tapered-congestion-control.md:3)). At commit `5d9129da`, Vox still installs `IdleRestartConfig` ([quic.rs:285](crates/vox-core/src/transport/quic.rs:285)), which constructs and restarts only `VoxCubic` ([congestion.rs:56](crates/vox-core/src/transport/congestion.rs:56), [congestion.rs:82](crates/vox-core/src/transport/congestion.rs:82)). The three-tier design is not yet safe or sufficiently specified for implementation.

## 1. Queue test

The threshold is not portable across the proposed path classes.

| Path | Effective threshold | Likely error | Consequence |
|---|---:|---|---|
| 1 Gbit/s, 2 ms | 4 ms = 500 KB = 2 BDP | A 1-BDP queue adds only 2 ms and is invisible | Tail loss is treated as random; tier 2 ignores it until the loss cap |
| 50 ms WAN | 20 ms = 0.4 BDP | A ¼-BDP queue or low-delay AQM is invisible | Early congestion drops look non-congestive |
| 20 Mbit/s, 60 ms | 24 ms = 60 KB = 0.4 BDP | CoDel-scale delay is invisible; correlated radio jitter can instead exceed 24 ms | False negatives under AQM and false positives under radio scheduling jitter |

CoDel’s recommended target is 5 ms, far below the proposed 20–24 ms WAN/cellular thresholds ([RFC 8289](https://www.rfc-editor.org/rfc/rfc8289.html)). Consequently, drop-only CoDel can signal real congestion while this classifier says “no queue.”

Further defects:

- A last-finished-round minimum is stale by one RTT. It cannot establish that a queue was present behind the particular loss being classified.
- The proposed sample is raw `now - sent` ([ADR-024:105](docs/adr/ADR-024-tapered-congestion-control.md:105)); that includes peer ACK delay. The current implementation uses the same raw calculation for HyStart++ ([congestion.rs:338](crates/vox-core/src/transport/congestion.rs:338)). A round minimum suppresses one delayed ACK, but not a round in which all ACKs are delayed or ACK policy changes.
- No minimum sample count is specified for the classifier, unlike current HyStart++, which requires eight samples ([congestion.rs:290](crates/vox-core/src/transport/congestion.rs:290)).
- A 10-second windowed minimum forgets a real propagation baseline after ten seconds of persistent queueing. Once the queued RTT becomes the new “base,” continuing tail loss can again appear queue-free.
- After a path RTT increase, the intentional ten-second false-positive period sacrifices performance; after a persistent standing queue, the opposite false negative is more dangerous.

The test is calibrated only for 200 Mbit/s/10 ms, where 4 ms happens to equal 0.4 BDP ([ADR-024:124](docs/adr/ADR-024-tapered-congestion-control.md:124)). It is not a generally valid congestion discriminator.

## 2. “No cut” and the 5% cap

No cut is unsafe whenever congestion produces little measured queue:

- A token-bucket policer drops above its configured rate without maintaining a queue. Vox can keep probing above the policer indefinitely.
- Drop-only CoDel or another AQM can keep delay below the threshold while intentionally dropping congestion signals.
- With a responsive competing flow, Vox can take bandwidth until the competitor retreats. Vox’s own loss fraction can then settle below 5%, even though the competitor has been starved. A per-flow loss ratio is not a fairness measurement.
- A deep buffer is initially detected, but if cross traffic keeps it persistently occupied for longer than the base-RTT window, the baseline can ratchet upward and hide the standing queue.

I do not find proof that tier 2 necessarily causes sustained classic congestion collapse: if the cap is measured correctly, sustained ignored loss is bounded near 5%, and the cap is a real brake. But the ADR does not establish safety. It permits bufferbloat, persistent wasted capacity, and starvation below the cap; the rolling estimator also permits larger transient bursts.

Eight rounds is not a stable time horizon: approximately 16 ms at 2 ms RTT, 400 ms at 50 ms, and 480 ms at 60 ms. The ADR also does not define how batched `lost_bytes` are attributed to send rounds. Quinn supplies packet number on `on_sent`, but its congestion callback supplies only the newest lost send time, persistent-congestion flag, and aggregate lost bytes ([quinn congestion.rs:18](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/congestion.rs:18), [quinn congestion.rs:48](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/congestion.rs:48)). The ADR must define the accounting algorithm and the exact `>` versus `>= 5%` boundary.

There is also a tier-3 safety hole. Quinn represents ECN by calling `on_congestion_event` with `lost_bytes == 0` ([quinn congestion.rs:53](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/congestion.rs:53)). Stock BBR merely adds `lost_bytes` and ignores the persistent-congestion flag ([BBR:468](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/congestion/bbr/mod.rs:468)); zero therefore does not enter its loss state ([BBR:623](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/congestion/bbr/mod.rs:623)). A straight port would ignore ECN and persistent congestion unless the taper explicitly intercepts both.

The single ¼-BDP drop-tail run demonstrates that an uncapped controller can be grossly unfair. It does not demonstrate that 5% is safe across policers, AQM, deep buffers, RTTs, or competing-flow counts.

## 3. Tier-3 trial

“Loss share does not climb with rate” is not a sound discriminator by itself.

- A policer or AQM can hold loss probability approximately flat as rate rises.
- A responsive competing flow can retreat as Vox accelerates, flattening Vox’s loss fraction and creating a false pass.
- If a competitor leaves during the trial, loss falls and rate rises, also creating a false pass.
- If a competitor arrives after a successful trial, the only continuing exits are two rounds of detected queueing or loss below 2.5% ([ADR-024:185](docs/adr/ADR-024-tapered-congestion-control.md:185)). High no-queue loss after the trial does not force an exit, so a false success can remain unfair indefinitely.
- Bursty random loss can exceed the failure threshold and wrongly bar BBR. Conversely, a burst already present at entry raises the baseline and makes subsequent heavy loss easier to accept.
- A capacity drop or newly arriving flow makes delivery fall below 50% of the preceding ten-second best, so the entry condition can specifically select an adverse path change as evidence for BBR.

At a 5% entry share, the failure threshold is 8%, not “does not climb”: `max(7.5%, 8%)`. Loss can rise by 60% and the trial still passes. The one congested run’s 4.3%→15.7% rise is easy to detect, but it does not validate the boundary cases.

The back-off protects only against detected failed trials. It does nothing after a false success. The “at most 2 s” claim also excludes unfairness accumulated in tier 2 before entry and after a false pass. “First 20 rounds and 2 s” needs an exact state-machine rule: stop on either limit, or wait for both.

There is an internal contradiction: rule 3 says queueing takes tier 3 to tier 2 “at once” ([ADR-024:93](docs/adr/ADR-024-tapered-congestion-control.md:93)), while the detailed rule requires two rounds ([ADR-024:185](docs/adr/ADR-024-tapered-congestion-control.md:185)).

### BBR integration gap

The statement that `BbrConfig` cannot be seeded with a current rate is correct: it exposes only the initial window ([BBR:515](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/congestion/bbr/mod.rs:515)), and construction resets bandwidth, mode, minimum RTT, pacing rate, and round state ([BBR:63](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/congestion/bbr/mod.rs:63)).

However, the proposed port still cannot directly seed or control quinn’s actual pacer through `Controller`:

- `ControllerMetrics::pacing_rate` is documented as a qlog metric ([quinn congestion.rs:68](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/congestion.rs:68)).
- It is consumed in the qlog-only metrics path ([paths.rs:189](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/connection/paths.rs:189)).
- The real sender pacer is called with smoothed RTT and congestion window, not the controller’s reported pacing rate ([connection/mod.rs:623](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/connection/mod.rs:623)). It is a userspace token-bucket pacer based on `1.25 × cwnd / RTT` with 2 ms burst intervals ([pacing.rs:7](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/connection/pacing.rs:7), [pacing.rs:91](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/connection/pacing.rs:91)).

Therefore “seeded with the current rate” is not yet an executable design. The ADR must either add a pacing-control seam, describe a deliberate window-based approximation and remeasure it, or acknowledge a quinn patch/fork. It must also define the complete BBR state hand-off, not just `rate` and `cwnd`. Quinn itself labels this BBR implementation experimental ([BBR:19](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/congestion/bbr/mod.rs:19)).

## 4. Fairness comparator

Stock quinn Cubic is a useful same-stack control, but it is not kernel TCP.

- Stock quinn Cubic remains in exponential slow start until loss ([cubic.rs:111](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/congestion/cubic.rs:111)). Vox’s controller adds HyStart++ ([congestion.rs:217](crates/vox-core/src/transport/congestion.rs:217)). Current CUBIC guidance recommends HyStart++ precisely because delay-based exit changes overshoot and loss behavior ([RFC 9438](https://www.rfc-editor.org/rfc/rfc9438.html)).
- TCP can use PRR to control transmissions during recovery; quinn’s Cubic immediately cuts `cwnd` and suppresses growth for acknowledgements of pre-recovery packets ([cubic.rs:167](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/congestion/cubic.rs:167)). PRR materially changes burst-loss recovery ([RFC 6937](https://www.rfc-editor.org/rfc/rfc6937.html)).
- Quinn uses fixed packet and time thresholds for loss detection ([connection/mod.rs:1700](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/connection/mod.rs:1700), [connection/mod.rs:1728](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/connection/mod.rs:1728)); TCP RACK has an adaptive reordering window and retransmission-aware timing ([RFC 8985](https://www.rfc-editor.org/rfc/rfc8985.html)).
- Quinn’s userspace 2 ms burst pacer is not a kernel TCP pacing implementation.
- Both QUIC flows share QUIC packetization. Vox’s 8192-byte MTU is only a conditional ceiling; hosts without the required receive buffer use 1452 ([quic.rs:233](crates/vox-core/src/transport/quic.rs:233)). Kernel TCP normally has different segmentation and offload behavior, which changes loss events per byte.

Thus the race measures “Vox taper versus stock quinn Cubic under identical QUIC recovery and packetization.” That is valuable, but it does not prove TCP friendliness. The ADR should call it a quinn-Cubic control and require a separately provisioned kernel-TCP experiment before making claims about TCP fairness.

## 5. False or premature statements

- “Tier 1 — quinn’s Cubic, unchanged” is false when read literally ([ADR-024:84](docs/adr/ADR-024-tapered-congestion-control.md:84)). Current Vox builds its own Cubic with HyStart++ and idle restart ([congestion.rs:52](crates/vox-core/src/transport/congestion.rs:52), [congestion.rs:217](crates/vox-core/src/transport/congestion.rs:217)).
- “All three tiers read one helper, `PathSignals` in ... congestion.rs” is false as current-state prose ([ADR-024:105](docs/adr/ADR-024-tapered-congestion-control.md:105)). That file contains `IdleRestart` followed directly by `VoxCubic` ([congestion.rs:67](crates/vox-core/src/transport/congestion.rs:67), [congestion.rs:153](crates/vox-core/src/transport/congestion.rs:153)); no tier state or `PathSignals` exists.
- “It stays on ... quinn’s own controllers” is inconsistent with both current `VoxCubic` and the planned Vox-owned BBR port ([ADR-024:203](docs/adr/ADR-024-tapered-congestion-control.md:203)).
- “The congested arms ... prove them” states M24.2 as accomplished even though M24.2 is planned later ([ADR-024:206](docs/adr/ADR-024-tapered-congestion-control.md:206), [ADR-024:223](docs/adr/ADR-024-tapered-congestion-control.md:223)).
- The present-tense controller, switching, state-handoff, `PathSignals`, and positive-consequence prose should consistently say “is to” or “must” until M24.3/M24.4 land.
- The 2026-10-01 date is a continuation beneath an `Updated` field whose actual declared value remains 2026-09-25 ([ADR-024:7](docs/adr/ADR-024-tapered-congestion-control.md:7)). The repository ADR inspector consequently reports the earlier value.

No finding on these points:

- `Cargo.lock` does contain quinn-proto 0.11.18 ([Cargo.lock:1659](Cargo.lock:1659)).
- Quinn’s default controller is Cubic ([transport.rs:399](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/config/transport.rs:399)).
- `RttEstimator::min` is a lifetime minimum ([paths.rs:298](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/connection/paths.rs:298), [paths.rs:325](~/.cargo/registry/src/<index>/quinn-proto-0.11.18/src/connection/paths.rs:325)).
- The assertion that stock `BbrConfig` cannot accept a delivery-rate seed is correct.
- I cannot verify the named model-reviewer list from the requested artifacts, so I do not call it false.

## 6. Statistics

Every 2026-10-01 arm is explicitly one run, under load about 80, with emulator lateness up to 18 ms on a 10 ms path ([ADR-024:50](docs/adr/ADR-024-tapered-congestion-control.md:50)). Rates are reported as means without durations, per-second dispersion, seeds, or independent-run variance.

Repeat because there is smoke:

1. The queue threshold. Random-loss p90 is 4.3 ms, the threshold is 4 ms, and congested p10 is 4.7 ms. Those margins are smaller than the reported typical emulator lateness of 2–6 ms.
2. The 5% cap. Its successful shallow-buffer run reports 4.3% loss, only 0.7 percentage point below the selected cap.
3. The “flat random loss” discriminator. 5.07%→5.03% is a 0.04-point difference from two separate controller runs, not evidence of a stable rate/loss slope.
4. The changing-link behavior. One clean→lossy→clean cycle cannot establish hysteresis or absence of flapping.

Large enough to trust directionally at the exact tested condition:

- No-cut versus a 0.85 cut: 2.77× versus 1.01×.
- Uncapped tier 2’s shallow-buffer unfairness: 5.26×.
- BBR’s random-loss benefit and shallow-buffer unfairness: 7.68× and 7.22×.
- The earlier clean-LAN BBR collapse has repeated evidence—five of six runs at 37–44%, plus a second emulator configuration ([ADR-024:43](docs/adr/ADR-024-tapered-congestion-control.md:43)).

Those large effects justify the architecture problem. They do not validate the chosen 4 ms/40%, 5%, eight-round, or trial thresholds across path classes.

The repository was left unchanged. Work item `#154` is named by the reviewed commit, but `awa status --json` could not verify its phase or health because the GitHub API connection failed.

## VERDICT

BLOCK

1. Replace or constrain the queue classifier so it handles low-RTT links, WAN/cellular jitter, ACK delay, persistent standing queues, and shallow AQM; define sample-count and baseline-aging semantics exactly.
2. Define exact loss attribution and cap boundaries, and add a safety invariant independent of per-flow loss share—queue latency, ECN/persistent-congestion response, and continuous fairness fallback.
3. Redesign tier-3 admission as a controlled, continuously monitored probe that cannot remain in tier 3 after a false pass; specify behavior for competing-flow arrival/departure and bursty loss.
4. Specify immediate tier-3 handling for ECN and persistent congestion, and resolve the “at once” versus two-round contradiction.
5. Resolve the quinn pacing seam and define the full BBR state hand-off. If actual pacing cannot be controlled without changing quinn, document and measure the chosen alternative.
6. Rename the comparison as a quinn-Cubic control and obtain separate kernel-TCP evidence before claiming TCP fairness.
7. Correct current-code inaccuracies and future-tense violations, then extend evidence to 1 Gbit/s/2 ms, 50 ms WAN, 20 Mbit/s/60 ms jitter, policers, CoDel/fq_codel, and deep drop-tail buffers. Repeat only the borderline arms identified above; the large-effect arms do not need repetition absent new smoke.