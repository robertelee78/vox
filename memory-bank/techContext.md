# techContext

## Implementation sources; existence does not prove behavior

- [crates/vox-core/src/node/history_stream/hints.rs](../crates/vox-core/src/node/history_stream/hints.rs)

## Executable tests; existence does not prove they pass

- [crates/vox-tui/tests/support/optional_proof.rs](../crates/vox-tui/tests/support/optional_proof.rs)
- [crates/vox-tui/tests/support/sync_pair.rs](../crates/vox-tui/tests/support/sync_pair.rs)

## Reviewed requirement: real-product-proof

A valid feature proof drives the shipped vox binary or a real wire peer and asserts what a user gets. No unit or in-process library tests qualify a feature. Extend existing journeys before adding files; retain exact commands, outputs, exit status and artifacts.

Applicability: `{"conditions": {}, "scope": "repository"}`.
Reviewed value: `"Real binary, real user outcome"`.
Evidence: [docs/adr/ADR-018-quality-bar-and-product-proof.md](../docs/adr/ADR-018-quality-bar-and-product-proof.md).

## Reviewed requirement: no-magic-clock-verdict

Detect a wedge through product or structural observations. Arbitrary elapsed time cannot make a progressing process fail. An explicitly requested emergency timebox yields NO RESULT or CANNOT MEASURE, not a product verdict. Ordinary machine load is not grounds to waive latency failures.

Applicability: `{"conditions": {}, "scope": "repository"}`.
Reviewed value: `"Measure progress and causal wedges, not elapsed silence"`.
Evidence: [docs/adr/ADR-018-quality-bar-and-product-proof.md](../docs/adr/ADR-018-quality-bar-and-product-proof.md).

## Reviewed requirement: proof-verdict-and-mutant

Every proof failure must identify PRODUCT, PRODUCT (staging), APPARATUS or CANNOT MEASURE from actual evidence. Each claim needs a mutant that fails its own PRODUCT assertion; interruption, unavailable staging and CANNOT MEASURE do not count as a mutant bite.

Applicability: `{"conditions": {}, "scope": "repository"}`.
Reviewed value: `"Attributed failures and biting mutants"`.
Evidence: [docs/adr/ADR-018-quality-bar-and-product-proof.md](../docs/adr/ADR-018-quality-bar-and-product-proof.md).

## Reviewed requirement: targeted-on-demand-qe

Run a proof once in the relevant profile; repeat only on smoke and say why. A verifier does not rerun the fixer's greens. Optional diagnostics block neither CI nor release and must say OPTIONAL PROOF NOT RUN when omitted. Spikes are run and reported, not added to gates.

Applicability: `{"conditions": {}, "scope": "repository"}`.
Reviewed value: `"Targeted, evidence-driven QE"`.
Evidence: [docs/adr/ADR-018-quality-bar-and-product-proof.md](../docs/adr/ADR-018-quality-bar-and-product-proof.md).

## Reviewed implementation: scratch-profile-example

The inspected sync_pair apparatus starts each member CLI and daemon with both VOX_DATA_DIR and VOX_CONFIG_DIR under its scratch member directory. Use this source as an isolation example; current operator safety instructions remain authoritative.

Applicability: `{"conditions": {"revision": "d433edbfba2d438a19765cf870f9b5d4ca083e76"}, "scope": "repository"}`.
Reviewed value: `"Both data and config paths isolated"`.
Evidence: [crates/vox-tui/tests/support/sync_pair.rs](../crates/vox-tui/tests/support/sync_pair.rs).
