# systemPatterns

## Planning sources; approval and current applicability require review

- [docs/adr/ADR-018-quality-bar-and-product-proof.md](../docs/adr/ADR-018-quality-bar-and-product-proof.md)
- [docs/adr/ADR-037-a-joined-room-converges-without-waiting.md](../docs/adr/ADR-037-a-joined-room-converges-without-waiting.md)

## Reviewed implementation: inventory-is-not-authority

At the inspected revision, HintInbox stores scalar hints by room and peer. Hints carry no authority or resource charge; in-flight owners stay immutable, newer queued heads coalesce, equal-size distinct heads remain fork evidence, and retirement advances only the affected scope generation. This source observation is not runtime acceptance.

Applicability: `{"conditions": {"revision": "d433edbfba2d438a19765cf870f9b5d4ca083e76"}, "scope": "repository"}`.
Reviewed value: `"Scoped scalar hints, immutable active ownership"`.
Evidence: [crates/vox-core/src/node/history_stream/hints.rs](../crates/vox-core/src/node/history_stream/hints.rs).

## Reviewed delivery: empty-round-feedback-lesson

Observed 2026-10-25: The #1021 RCA records a feedback path from bounded completion to settlement to another unchanged own-head offer: about 31,500 empty rounds per peer in one 40.47 s observation. The reason the peer receipt remained behind was unresolved. Preserve the distinction between a measured loop and an unproven underlying cause; no CPU cap, timer or guessed receipt establishes a fix.

Applicability: `{"conditions": {"task": "robertelee78/vox#1021"}, "scope": "repository"}`.
Reviewed value: `"Repeated completion can manufacture unchanged demand"`.
Evidence: [https://github.com/robertelee78/vox/issues/1021](https://github.com/robertelee78/vox/issues/1021).


## Candidate lesson: signed Head, actual receipt and owned transient work

In the reviewed #1021 candidate, authenticated signed Head knowledge, the peer's exact role-contiguous receipt, and an admitted transient serving dependency are separate facts. Only a fresh receipt whose position/hash matches the accepted OWN chain may change ReadBy; signed Head size is not that receipt. `None` asserts no receipt, rather than zero or full acknowledgement. Higher/conflicting valid own Head evidence still governs rollback/write refusal independently. A static older-header gap with no automatic producer must not become an endless Busy retry: ADR-037 leaves ordinary old history to explicit Older. Later same-Head role progress needs a retained semantic handoff, not another timer or a fabricated ACK.

Applicability: inspected candidate source `1071c0278523b102dbf07ccae014e4e92141d2f7` and composed source tree `6d4ea31d57ced2e4f48de7073f242e542455534a` (commit `a32f715b10021293f7a5e42b38986dfb2453b727`). These are reviewed candidate observations, not a claim that current main contains the implementation or that every related journey passes. Later recovered prefix5/Head137/missing-header6 evidence does not supply the original feedback run's unrecorded wire answer or the missing header's kind/body.
Evidence: [ADR-037](../docs/adr/ADR-037-a-joined-room-converges-without-waiting.md), [ADR-038](../docs/adr/ADR-038-daemons-trust-daemons-and-sessions-are-presence.md), [#1021 RCA](https://github.com/robertelee78/vox/issues/1021#issuecomment-6392036366); `channel/sparse_history.rs`, `history_stream/client.rs`, `hints.rs`, `runtime.rs` and actor receipt application at the recorded revisions. Local P008 and its independently adjudicated own controls support specific partial/full-receipt outcomes; they are not whole-story acceptance.

## Candidate lesson: admitting an own question is not committed history

A newly queued canonical own-Head question is scheduling work: preserve its offered tally and exact wake without reporting fetched data or a store commit solely for the RAM insertion. The durable commit marker belongs to the transaction that actually committed, including changed-refusal removal even if queue insertion adds nothing. Ordinary missing-history hint admission retains its existing useful-admission/nonempty contract; actual sent metadata and body transfers remain visible. Keep data credit separate from the wake needed to run admitted work. On a fresh connection, a genuine metadata response may be served while the outbound unchanged-history fetch is empty; bind the direction, current completed root and saved refusal tuple instead of equating all served rounds with old-body refetch.

Applicability: the same candidate1071/composed6d4 source. P007 exposed a RAM own-question insertion credited to fetched history and committed-work maintenance; P008 exercised the corrected handoff. Neither observation licenses suppressing genuine commits, metadata serving, callbacks, receipt progress or failure/backoff.
Evidence: [#1021](https://github.com/robertelee78/vox/issues/1021), [ADR-038](../docs/adr/ADR-038-daemons-trust-daemons-and-sessions-are-presence.md); `history_stream/runtime.rs::finish_inventory`, `server.rs`/`serve`, `channel/sparse_history.rs::history_write_tracked` and `forget_history_decline`. Exact source and runtime references are retained with the review proposal; byte hashes establish provenance, not the truth of an interpretation.

## Diagnosed lesson: retained offline work is not a runnable lane owner

An exact continuation may remain owed after routing to an offline author without being runnable. In the diagnosed quiet-store journey, a charge-free foreground READY Flow for absent Bob blocked connected Alice's independent queued work even though sampled physical capacity was free. Matching-flow selection required the same peer, while the fresh-work gate treated any READY owner as occupying the global live lane. Retain the whole continuation and its authority/lifecycle fences behind its real connection dependency; retained ownership must not by itself reserve unrelated runnable selection. Moving ownership must not reconstruct a hint, discard work, fake an ACK, raise a cap or invent a timer.

Applicability: source1071/composed6d4 and two scoped shipped-Status pairs from the operator-stopped original quiet-store P001. They establish a reachable selection blockage, not a permanent empty pool, an unrecorded wire query, a completed PRODUCT assertion or a runtime-fixed result. The corrective offline handoff is a separate source candidate; integration, independent review and the unchanged real user journey remain to be established at this proposal's evidence boundary. It is not claimed landed or release-ready.
Evidence: [#1021](https://github.com/robertelee78/vox/issues/1021), `actor/bounded_sync.rs` same-peer selection/reroute/READY gate and actor connection discovery. Inspect the source-bound pending handoff evidence before applying a candidate repair; AWA retains delivery status.
