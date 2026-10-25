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
